"""Wave 6 : the immutable verification binding and the submitted observation.

`local_observe/platform/verification_records.py` and the `Store` methods it attaches are under test here:
`VerificationPolicy(document)`, `Store(..., verification_policy=None)`, `Store.get_verification_binding`,
`Store.put_verification` and `Store.get_verification`, exactly as frozen in the wave-6 contract. These
tests were written against that contract alone — the implementation was drafted elsewhere and was not
read — so where the contract names a word (`matched`, `origin-ambiguous`, `pre-execution-window`,
`not-captured`) the word is asserted, and where it names only a shape (a fixed sentence, a defensive
copy, a digest of the captured origin) the *property* is asserted and never the spelling.

The failure boundaries that matter here, and the reason almost every test below is a refusal:

* **The binding is proposal-time provenance, not a live lookup.** It is captured once, inside the action's
  own transaction, from the events the action explicitly cites, and nothing afterwards may re-derive it:
  not a policy restart, not a claim, not an outcome, not a reconciliation, not a resolved incident. So the
  numeric meaning a verdict is judged against is the one that was reviewed when the alert fired — a policy
  edit may not silently move the goalposts under an open incident, and an operator who re-reads a binding
  months later reads the mapping that was in force then.
* **A stored observation is immutable and its identity is narrow.** `verification_id` covers
  execution + binding + normalized window and nothing else, so a *changed statement under the same
  identity* is a conflict rather than a second row, a *different window* is a different check, and the
  submitting identity is not part of it. Already-accepted statements are never re-graded by a later clock
  or a later execution status.
* **The server judges, the caller does not.** No verdict field is accepted; the verdict is derived in a
  fixed precedence, and the answer for anything short of a complete, in-scope, post-terminal read is
  `unknown` with a named reason — never `cleared`, and never a refusal that hides the evidence.
* **A `not_cleared` on a `succeeded` run changes nothing about the incident.** That is the whole point of
  remediation invariants ("exit zero alone does not determine recovery") and it is asserted here against the durable
  rows,
  not the log line: the incident stays open, the action and execution keep the runner's own outcome, and
  the only thing this write added is one bounded `verification.recorded` audit row.
* **The write path is outside the four audited action attempts, and inside the existing authority rules.**
  A refused verification write must not grow an `action.refused` row (that taxonomy is pinned to
  propose/decide/claim/outcome), and a verifier is an *allowlisted producer*, not a new role.

Realistic fixtures, not shapes invented for the test: the event is `detections.event` with a real
`metric-threshold` evidence reference; the action goes through the real `action_policy` over a temporary
inventory index; the execution is a real claim with a runner token; the receipt is built by
`store.client.build_outcome` — the function both backends call — so its query kind, approved parameters,
window, row count and truncation flag are the facade's own. Databases are temporary files; no network, no
live state, no wall-clock dependency (the real-clock path is exercised with a window derived from the
actual instant, so it cannot drift into a refusal).
"""
import copy
import datetime as dt
import json
import re
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from local_observe.inventory import index
from local_observe.inventory.validation import canonical, digest, read_document, timestamp, utc_text
from local_observe.platform import state
from local_observe.platform.detections import event as canonical_event
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, StateError, Store
from local_observe.platform.verification_records import VerificationPolicy
from local_observe.store import client as facade
from local_observe.store.client import MetricSample, Window

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-08T12:00:00Z')
PROPOSE_NOW = NOW + dt.timedelta(minutes=3)
TERMINAL = NOW + dt.timedelta(minutes=5)
RECORD_NOW = NOW + dt.timedelta(minutes=20)
EXPIRES = utc_text(NOW + dt.timedelta(hours=1))
DETECTOR = 'threshold-detector'
RULE = 'inspect.cpu'
RULE_VERSION = '3'
SERIES = 'lo_cpu'
PIN = 'a' * 64
OTHER_PIN = 'b' * 64
LONG_LABEL = 'x' * 128
WINDOW_SECONDS = 300
VERIFIER = Actor('verify-worker', 'producer')
SECOND_VERIFIER = Actor('second-verifier', 'producer')
UNLISTED = Actor('test-detector', 'producer')
HUMAN = Actor('operator', 'human')
AGENT = Actor('agent-1', 'proposer')
RUNNER = Actor('runner-1', 'executor')
READER = Actor('reader-1', 'reader')
SUMMARY = Actor('summary-1', 'summary')
BINDING_FIELDS = ('action_id', 'binding_id', 'origin', 'reason', 'status')
RECORD_FIELDS = ('action_id', 'binding_id', 'execution_id', 'outcome', 'origin', 'receipt', 'reason',
                 'recorded_at', 'recorded_by', 'sampled_at', 'samples', 'value', 'verdict',
                 'verification_id', 'window')
MAPPING_FIELDS = ('artifact_sha256', 'comparison', 'condition', 'metric_name', 'parameters', 'query_type',
                  'resource_id', 'rule_id', 'rule_version', 'source', 'threshold', 'window_seconds')
SHA256 = re.compile(r'^[0-9a-f]{64}$')
_AUTO = object()
_CONFIGURED = object()


class VerificationFixture(unittest.TestCase):
    """The shared scenario: a real open incident, a bound action, a terminal execution, one statement.

    Kept as a base class rather than module-level helpers because every test needs a temporary database
    and an inventory index, and because the fixture asserts its own preconditions (an event really
    accepted, an action really bound, an execution really terminal) — a scenario that silently failed to
    reach the state a test names would otherwise be asserting something else.
    """

    def setUp(self) -> None:
        """Build the inventory index and the reviewed action policy every scenario is proposed under."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.declared = index_document()
        self.host = self.declared['resources'][0]['id']
        self.service = self.declared['resources'][1]['id']
        self.inventory = self.root / 'inventory.db'
        index.build(self.declared, self.inventory, 'fixture', now=NOW)
        self.gate = action_policy(self.inventory, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})

    # ------------------------------------------------------------- the reviewed policy

    def mapping(self, **changes) -> dict:
        """One reviewed mapping: the detector revision, the series and the numeric meaning of 'cleared'."""
        fields = {'source': DETECTOR, 'rule_id': RULE, 'rule_version': RULE_VERSION, 'condition': RULE,
                  'resource_id': self.host, 'query_type': 'metric-threshold',
                  'parameters': {'resource_id': self.host, 'rule_id': RULE, 'artifact_sha256': PIN},
                  'metric_name': SERIES, 'threshold': 90.0, 'comparison': 'lt',
                  'window_seconds': WINDOW_SECONDS, 'artifact_sha256': PIN}
        fields.update(changes)
        return fields

    def document(self, *, mapping=None, verifiers=None, mappings=None, **top) -> dict:
        """A valid policy document, rebuilt from scratch every call, changed only by what is under test."""
        document = {'schema_version': 1,
                    'verifiers': [actor.identity if isinstance(actor, Actor) else actor for actor in
                                  (verifiers if verifiers is not None else [VERIFIER, SECOND_VERIFIER])],
                    'mappings': list(mappings if mappings is not None
                                     else [mapping if mapping is not None else self.mapping()])}
        document.update(top)
        return document

    def policy(self, **changes) -> VerificationPolicy:
        """`VerificationPolicy` over one freshly built document."""
        return VerificationPolicy(self.document(**changes))

    # ------------------------------------------------------------- the platform scenario

    def open(self, name='case', *, policy=_AUTO) -> Store:
        """Open `<name>.db`. `_AUTO` is this checkout's off default; pass `None` to say so explicitly."""
        path = self.root / (name + '.db')
        if policy is _AUTO:
            return Store(path)
        return Store(path, verification_policy=policy)

    def fire(self, store: Store, *, minute=0, status='firing', source=DETECTOR, rule=RULE,
             rule_version=RULE_VERSION, resource=None, parameters=_AUTO,
             query_type='metric-threshold', at=None) -> dict:
        """Intake one canonical event and return its ids, asserting intake really accepted it."""
        resource = resource or self.host
        end = NOW + dt.timedelta(minutes=minute)
        window = {'start': utc_text(end - dt.timedelta(minutes=1)), 'end': utc_text(end)}
        if parameters is _AUTO:
            parameters = {'resource_id': resource, 'rule_id': rule, 'artifact_sha256': PIN}
        payload = canonical_event(source, resource, rule, 'threshold', status, window, parameters,
                                  query_type=query_type, version=rule_version)
        result = store.intake(payload, Actor(source, 'producer'), now=at or end)
        self.assertEqual(result['status'], 'accepted', 'the fixture event must be a fresh acceptance')
        return {'event_id': result['event_id'], 'incident_id': result['incident_id'], 'event': payload}

    def request(self, incident_id, evidence, *, targets=None, retry_key='once') -> dict:
        return {'retry_key': retry_key, 'incident_id': incident_id, 'action': 'inspect', 'version': '1',
                'targets': list(targets if targets is not None else [self.host]), 'parameters': {},
                'evidence': list(evidence), 'expires_at': EXPIRES}

    def propose(self, store: Store, incident_id, evidence, *, targets=None, retry_key='once',
                actor=AGENT, now=PROPOSE_NOW) -> tuple[dict, dict]:
        """Propose an action and return the client's request beside the store's answer."""
        payload = self.request(incident_id, evidence, targets=targets, retry_key=retry_key)
        return store.propose_action(payload, actor, self.gate, now=now), payload

    def bound(self, name='case', *, policy=_CONFIGURED, evidence=None, targets=None, retry_key='once',
              binding_actor=READER, **event_fields) -> dict:
        """One store holding an open incident and a proposed action, with the binding already read back.

        `evidence` is a list of event ids the action cites; the default cites the single event this
        scenario fired. Nothing here is simulated: the binding is read through the public read, so every
        test that starts from `bound()` also pins that the read works for a reader-role credential.
        """
        if policy is _CONFIGURED:
            policy = self.policy()
        store = self.open(name, policy=policy)
        fired = self.fire(store, **event_fields)
        cited = evidence if evidence is not None else [fired['event_id']]
        result, payload = self.propose(store, fired['incident_id'], cited, targets=targets,
                                      retry_key=retry_key)
        case = {'store': store, 'name': name, 'event_id': fired['event_id'], 'events': [fired],
                'incident_id': fired['incident_id'], 'action_id': result['action_id'],
                'request': payload, 'policy': policy}
        case['binding'] = store.get_verification_binding(result['action_id'], binding_actor)
        case['binding_id'] = case['binding']['binding_id']
        case['origin'] = case['binding']['origin']
        return case

    def executed(self, case: dict, outcome='succeeded', *, at=TERMINAL) -> dict:
        """Decide, claim and report `outcome`, leaving the execution in that proved state."""
        store = case['store']
        store.decide(case['action_id'], 'approved', HUMAN, now=PROPOSE_NOW)
        claim = store.claim_action(case['action_id'], RUNNER, self.gate,
                                  now=at - dt.timedelta(minutes=1))
        case['execution_id'] = claim['execution_id']
        case['runner_token'] = claim['runner_token']
        case['terminal'] = at
        if outcome is not None:
            store.execution_outcome(claim['execution_id'], outcome, RUNNER, claim['runner_token'], now=at)
        return case

    # ------------------------------------------------------------- one submitted statement

    def window(self, case, *, ends_at=None, seconds=WINDOW_SECONDS) -> dict:
        """The half-open ``[end - seconds, end)`` a statement is submitted for, normalised.

        The default ends six minutes after the execution went terminal, which is the shortest window that
        is entirely *after* the terminal instant: a default statement is therefore a definitive one, and
        every test that wants a stale or a partial read says so explicitly instead of inheriting a window
        that the server would have refused to judge on.
        """
        ends_at = TERMINAL + dt.timedelta(minutes=6) if ends_at is None else ends_at
        return {'start': utc_text(ends_at - dt.timedelta(seconds=seconds)), 'end': utc_text(ends_at)}

    def origin_of(self, case) -> dict:
        """The captured origin, or the reviewed mapping when this scenario never bound one.

        A test that attacks the no-binding path still needs a statement shaped like a real one, and the
        only honest way to build it is from the mapping the policy did review: falling back here is what
        keeps those refusals about the missing binding instead of about a fixture that could not be built.
        """
        return case['origin'] or self.mapping()

    def rows(self, case, window, values, *, at=None, resource=None, metric=None) -> list:
        """Bounded sample rows for the captured series, stamped inside the submitted window."""
        origin = self.origin_of(case)
        instant = utc_text(timestamp(window['end']) - dt.timedelta(seconds=60)) if at is None else at
        return [{'resource_id': resource or origin['resource_id'],
                 'metric_name': metric or origin['metric_name'], 'observed_at': instant, 'value': value}
                for value in values]

    def receipt(self, case, window, /, *, count=1, **changes) -> dict:
        """The exact six-field receipt one read of the captured origin would carry — facade-built.

        `build_outcome` is what both store backends call, so the query kind, the approved parameters, the
        window, the expiry and the row count are the facade's own answers and not a shape this file
        invented; `changes` is how a test states that the verifier's receipt *claimed* something else.
        """
        origin = self.origin_of(case)
        rows = [MetricSample(name=origin['metric_name'], value=1.0, resource_id=origin['resource_id'],
                             labels={'resource_id': origin['resource_id']}, timestamp=window['start'])
                for _ in range(count)]
        built = facade.build_outcome(facade.QUERY_KINDS[origin['query_type']], dict(origin['parameters']),
                                     Window(start=window['start'], end=window['end']), rows)
        document = built.receipt.as_dict()
        document.update(changes)
        return document

    def statement(self, case, *, window=_AUTO, outcome='available', receipt=_AUTO, samples=_AUTO,
                  **changes) -> dict:
        """One complete submitted observation: the six record keys, nothing else, changed as asked."""
        window = self.window(case) if window is _AUTO else window
        if samples is _AUTO:
            samples = self.rows(case, window, [70.0]) if outcome == 'available' else []
        if receipt is _AUTO:
            receipt = None if outcome != 'available' else self.receipt(case, window, count=len(samples))
        document = {'execution_id': case.get('execution_id', str(uuid.uuid4())),
                    'binding_id': case.get('binding_id', PIN), 'window': window, 'outcome': outcome,
                    'receipt': receipt, 'samples': samples}
        document.update(changes)
        return document

    def put(self, case, *, actor=VERIFIER, now=RECORD_NOW, **changes):
        """Submit one statement for `case` and return whatever the store answers, or let it raise."""
        return case['store'].put_verification(self.statement(case, **changes), actor, now=now)

    def stored(self, case, verification_id=None, actor=READER) -> dict:
        """Read back the stored document, defaulting to the id the last write in this test returned."""
        return case['store'].get_verification(verification_id or case['verification_id'], actor)

    # ------------------------------------------------------------- refusal shape

    def refused(self, thunk, *sentinels) -> str:
        """Assert the call is refused as a `StateError` with a fixed, safe sentence, and return it.

        The contract pins the *shape* of every failure ("fixed safe sentences, never payload
        interpolation") and not the wording, so wording is not asserted here. What is asserted is the
        part a regression can violate while still raising: one bounded single line, no JSON shape riding
        along, and none of the `sentinels` (values taken from the rejected input) echoed back.
        """
        with self.assertRaises(StateError) as caught:
            thunk()
        sentence = str(caught.exception)
        self.assertTrue(sentence, 'a refusal must name itself')
        self.assertNotIn('\n', sentence)
        self.assertLess(len(sentence), 200, 'a fixed sentence is short; a long one is a payload')
        for char in '{}':
            self.assertNotIn(char, sentence, 'a refusal sentence carries no caller document')
        for value in sentinels:
            self.assertNotIn(value, sentence, 'a refusal sentence never echoes a submitted value')
        return sentence

    def ops(self, store: Store, operation: str) -> list[dict]:
        """The stored audit rows of one operation, oldest first."""
        rows = [row for row in store.records('audit', 100) if row['operation'] == operation]
        return list(reversed(rows))


def index_document() -> dict:
    """The example declaration with both declared resources opted into remediation.

    Two opt-in targets are what makes the multi-target refusal testable through the real action policy
    instead of through a stub that would not prove the platform's own target rules still run.
    """
    document = read_document(ROOT / 'examples/inventory/declared.yaml')
    for resource in document['resources']:
        resource['attributes']['remediation_enabled'] = True
    return document


class PolicyTests(VerificationFixture):
    """The reviewed policy document: what it may say, how tightly it is bounded, and that it is frozen.

    A policy is the numeric meaning of a detector revision, so the interesting inputs are the ones that
    would otherwise be *interpreted*: a bool where a number belongs, an artifact pin that is merely
    absent, a second mapping for one reviewed revision, a document one byte too large, and the caller's
    own dict after the caller changed it.
    """

    def test_a_reviewed_document_builds_a_policy_that_outlives_its_source(self):
        """Mutating the caller's document — nested lists, nested dicts, the top level — changes nothing.

        This is the defensive-snapshot rule read where it can only be read: from the durable consequence.
        The store is handed a policy built from `document`, the caller then rewrites its own copy in six
        places, and the binding captured afterwards still names the reviewed threshold, the reviewed rule
        and the reviewed verifier list.
        """
        document = self.document()
        reviewed = copy.deepcopy(document)
        policy = VerificationPolicy(document)
        document['schema_version'] = 99
        document['verifiers'].append('sneaky-worker')
        document['mappings'].append(self.mapping(rule_id='other.rule'))
        document['mappings'][0]['threshold'] = 0.0
        document['mappings'][0]['comparison'] = 'gt'
        document['mappings'][0]['parameters']['rule_id'] = 'other.rule'

        case = self.executed(self.bound('snapshot', policy=policy))
        self.assertEqual(case['origin'], {**{key: reviewed['mappings'][0][key] for key in MAPPING_FIELDS},
                                         'event_id': case['event_id'], 'action_targets': [self.host]})
        self.refused(lambda: case['store'].put_verification(self.statement(case),
                                                            Actor('sneaky-worker', 'producer'),
                                                            now=RECORD_NOW))
        self.refused(lambda: case['store'].put_verification(self.statement(case), UNLISTED,
                                                            now=RECORD_NOW))
        recorded = self.put(case)
        case['verification_id'] = recorded['verification_id']
        self.assertTrue(self.stored(case)['verdict'] in ('cleared', 'not_cleared', 'unknown'))
        self.assertEqual(reviewed['mappings'][0]['threshold'], 90.0, 'the fixture document is the control')

    def test_every_container_a_policy_hands_back_is_a_fresh_copy(self):
        """An accessor that returned the stored object would let a reader rewrite the reviewed policy.

        The contract freezes the constructor and the snapshot rule, not the accessor's name, so the probe
        is over whatever public containers the object chooses to expose: each is mutated in place and
        then re-read. Zero surfaces is allowed and stated; a leaked surface is not.
        """
        policy = self.policy()
        probed = 0
        for name in sorted(attr for attr in dir(policy) if not attr.startswith('_')):
            try:
                value = getattr(policy, name)
            except Exception:  # pragma: no cover - a property that raises is not a readable surface
                continue
            if isinstance(value, (dict, list)):
                probed += 1
                original = copy.deepcopy(value)
                if isinstance(value, dict):
                    value['tampered'] = 'tampered'
                else:
                    value.append('tampered')
                self.assertEqual(getattr(policy, name), original,
                                 f'{type(policy).__name__}.{name} leaked the stored document')
        case = self.executed(self.bound('accessor', policy=policy))
        self.assertEqual(case['origin']['threshold'], 90.0, 'a tampered accessor result reached the binding')

    def test_the_document_vocabulary_is_exact_and_the_version_is_strictly_a_one(self):
        """An unknown or missing key, and a version that is not the integer 1, are refused, not clamped."""
        base = self.document()
        self.assertEqual(sorted(base), ['mappings', 'schema_version', 'verifiers'])
        for broken in (None, [], 'policy', 1, {'schema_version': 1, 'verifiers': [VERIFIER.identity]}):
            self.refused(lambda broken=broken: VerificationPolicy(broken))
        for field in ('schema_version', 'verifiers', 'mappings'):
            missing = {key: value for key, value in base.items() if key != field}
            self.refused(lambda missing=missing: VerificationPolicy(missing))
        widened = {**base, 'verifier_tokens': ['nothing']}
        self.refused(lambda: VerificationPolicy(widened), 'verifier_tokens')
        for version in (True, False, '1', 0, 2, 1.5, None):
            self.refused(lambda version=version: VerificationPolicy({**base, 'schema_version': version}))

    def test_verifier_ids_are_bounded_distinct_and_never_absent(self):
        """The allowlist is the write authority: empty, duplicated, unbounded or 33-deep is refused."""
        self.assertTrue(VerificationPolicy(self.document(verifiers=[VERIFIER.identity])))
        self.assertTrue(VerificationPolicy(self.document(
            verifiers=[f'verifier-{index}' for index in range(32)])))
        for broken in ([], [VERIFIER.identity, VERIFIER.identity], ['verify worker'], [''], ['x' * 129],
                       [True], [None], ['verify-worker/'], [42]):
            self.refused(lambda broken=broken: VerificationPolicy(self.document(verifiers=broken)))

    def test_a_mapping_names_every_reviewed_field_and_nothing_else(self):
        """Twelve keys, all required: a missing field is a guess and an extra field is an unreviewed knob."""
        self.assertEqual(sorted(self.mapping()), sorted(MAPPING_FIELDS))
        for field in MAPPING_FIELDS:
            without = {key: value for key, value in self.mapping().items() if key != field}
            self.refused(lambda without=without: VerificationPolicy(self.document(mapping=without)))
        self.refused(lambda: VerificationPolicy(self.document(
            mapping={**self.mapping(), 'severity': 'warning'})), 'severity')

    def test_the_pinned_artifact_is_required_and_the_read_scope_matches_it_exactly(self):
        """Missing historical pins are never guessed, and the receipt scope is the mapping, exactly.

        `parameters` is the scope a verifier's receipt will be checked against, so a missing artifact, an
        unapproved extra parameter or a value that disagrees with the field it names is a policy that
        cannot prove what it read — refused while it is still configuration.
        """
        for artifact in (None, '', PIN[:-1], PIN + 'a', PIN.upper(), 'z' * 64, 1, True):
            self.refused(lambda artifact=artifact: VerificationPolicy(self.document(
                mapping={**self.mapping(), 'artifact_sha256': artifact})))
        scope = self.mapping()['parameters']
        for parameters in ({'resource_id': self.host, 'rule_id': RULE},
                           {**scope, 'sample_id': 'extra'},
                           {'resource_id': self.service, 'rule_id': RULE, 'artifact_sha256': PIN},
                           {'resource_id': self.host, 'rule_id': 'other.rule', 'artifact_sha256': PIN},
                           {'resource_id': self.host, 'rule_id': RULE, 'artifact_sha256': OTHER_PIN},
                           {}, None, [scope], 'resource_id'):
            self.refused(lambda parameters=parameters: VerificationPolicy(self.document(
                mapping={**self.mapping(), 'parameters': parameters})))
        for query_type in ('gatus-result', 'sigma-count', 'metric_threshold', 'log-records', None, ''):
            self.refused(lambda query_type=query_type: VerificationPolicy(self.document(
                mapping={**self.mapping(), 'query_type': query_type})))

    def test_selector_fields_are_labels_and_the_resource_is_a_canonical_uuid(self):
        """The five selector fields and the series name are bounded labels; a resource is a UUID."""
        for field in ('source', 'rule_id', 'rule_version', 'condition', 'metric_name'):
            for value in ('', 'has space', 'x' * 129, None, True, 1):
                self.refused(lambda field=field, value=value: VerificationPolicy(self.document(
                    mapping={**self.mapping(), field: value})))
        for resource in (None, 'host-1', self.host.upper(), self.host[:-1], 'not-a-uuid', True):
            self.refused(lambda resource=resource: VerificationPolicy(self.document(mapping={
                **self.mapping(), 'resource_id': resource, 'parameters': {
                    'resource_id': resource if isinstance(resource, str) else self.host,
                    'rule_id': RULE, 'artifact_sha256': PIN}})))

    def test_the_numeric_meaning_is_finite_whole_and_never_a_boolean(self):
        """Threshold, comparison and window are the judgement: `True` is not a number, 59 is not a window.

        `Origin` in the existing verification unit is deliberately more permissive about an absent
        artifact and an absent series; the reviewed policy is not, so the permissive spellings are listed
        here as refusals rather than left to be discovered as bindings that could not be proven.
        """
        for threshold in (True, False, '90', None, float('nan'), float('inf'), float('-inf'),
                          10 ** 400, [90], {}):
            self.refused(lambda threshold=threshold: VerificationPolicy(self.document(
                mapping={**self.mapping(), 'threshold': threshold})))
        for comparison in ('==', 'LT', 'less', None, True, ''):
            self.refused(lambda comparison=comparison: VerificationPolicy(self.document(
                mapping={**self.mapping(), 'comparison': comparison})))
        for seconds in (True, 59, 86401, 0, -1, '300', 300.0, None, 300.5):
            self.refused(lambda seconds=seconds: VerificationPolicy(self.document(
                mapping={**self.mapping(), 'window_seconds': seconds})))
        for comparison in ('lt', 'le', 'gt', 'ge', 'eq'):
            self.assertTrue(VerificationPolicy(self.document(
                mapping={**self.mapping(), 'comparison': comparison})))
        for seconds in (60, 86400):
            self.assertTrue(VerificationPolicy(self.document(
                mapping={**self.mapping(), 'window_seconds': seconds})))

    def test_one_detector_revision_carries_exactly_one_reviewed_numeric_meaning(self):
        """Same selector tuple twice is a refusal even when the thresholds differ — no tie-break exists.

        Two mappings that select the same event could only bind by picking one, and which one wins would
        be a silent re-definition of a reviewed check. A different `rule_version` is a different revision
        and is allowed, which is the positive control: the refusal is about identity, not about size.
        """
        first = self.mapping()
        for twin in ({**first, 'threshold': 0.5}, {**first, 'comparison': 'gt'},
                     {**first, 'window_seconds': 60}, {**first, 'metric_name': 'other_series'},
                     {**first, 'artifact_sha256': OTHER_PIN}, {**first,
                                                                'parameters': dict(first['parameters'])}):
            self.refused(lambda twin=twin: VerificationPolicy(self.document(mappings=[first, twin])))
        distinct = {**first, 'rule_version': '4', 'parameters': dict(first['parameters'])}
        self.assertTrue(VerificationPolicy(self.document(mappings=[first, distinct])))
        self.assertTrue(VerificationPolicy(self.document(mappings=[first])))
        self.assertTrue(VerificationPolicy(self.document(mappings=[])))

    def test_the_policy_is_bounded_in_mappings_and_in_bytes(self):
        """65 mappings and a document over 64 KiB are both refused before any database is opened.

        The byte bound needs the widest legal field values to reach: 64 mappings of 128-character labels
        is roughly 77 KiB of canonical JSON, well past the cap, and every individual value is still a
        `label`, so this pins the whole-document rule rather than a field rule.
        """
        wide = []
        for offset in range(64):
            name = f'{LONG_LABEL[:120]}{offset}'
            wide.append(self.mapping(source=name, rule_id=name, rule_version=name, condition=name,
                                     metric_name=name,
                                     parameters={'resource_id': self.host, 'rule_id': name,
                                                 'artifact_sha256': PIN}))
        self.assertGreater(len(canonical(self.document(mappings=wide)).encode()), 65536,
                           'the fixture is not wide enough to be a byte-bound test')
        self.refused(lambda: VerificationPolicy(self.document(mappings=wide)))
        crowded = [self.mapping(rule_id=f'rule-{index}', condition=f'rule-{index}',
                                parameters={'resource_id': self.host, 'rule_id': f'rule-{index}',
                                            'artifact_sha256': PIN})
                   for index in range(65)]
        self.refused(lambda: VerificationPolicy(self.document(mappings=crowded)))
        self.assertTrue(VerificationPolicy(self.document(mappings=crowded[:64])))

    def test_a_policy_that_is_not_a_policy_never_reaches_a_database(self):
        """`verification_policy` is validated before the file is opened, so a bad knob creates nothing.

        The argument accepts `None` or a `VerificationPolicy`, and that is the whole vocabulary: a bare
        document (the shape an operator would hand a loader) is not silently accepted, because accepting
        it would mean one call site that turns a review typo into a live verification authority. The
        refusal has to happen before SQLite is touched, which is why the assertion is about the file that
        is not there.
        """
        for position, junk in enumerate((self.document(), 'verification-policy', 1, [], object(),
                                         {'verifiers': []})):
            path = self.root / f'never-{position}.db'
            self.refused(lambda path=path, junk=junk: Store(path, verification_policy=junk))
            self.assertFalse(path.exists(), 'a refused policy must not create or open a database')
            self.assertFalse(Path(str(path) + '-wal').exists())
        self.assertTrue(Store(self.root / 'none-is-off.db', verification_policy=None).path.exists())
        self.assertTrue(Store(self.root / 'default-is-off.db').path.exists())


class BindingCaptureTests(VerificationFixture):
    """What proposal-time capture proves, and every way it refuses to guess.

    The binding is written once, inside the action's own transaction, and is the only thing that later
    makes a verdict mean something: it names the reviewed numeric meaning *and* the event that supplied
    it. So each refusal below is a case where a plausible implementation would have bound something — a
    partial binding for a multi-target action, a re-derived binding after a policy edit, a guessed pick
    out of two matching events, a binding backfilled onto an action that predates the policy — and the
    contract's answer is an explicit `unbound` document plus an action that goes on unchanged.
    """

    def test_a_default_off_store_documents_no_binding_and_says_not_captured(self):
        """Off is not "unbound because nothing matched": it is "this build captured nothing".

        The two answers are different facts and an operator reads them differently, so the exact reason
        word is pinned, alongside the empty `binding_id`/`origin` that keeps a reader from inventing one.
        The same read is asserted for `verification_policy=None` (the accepted explicit off) so the two
        spellings of off cannot diverge.
        """
        for name, policy in (('off', _AUTO), ('none', None)):
            with self.subTest(policy=name):
                case = self.bound(name, policy=policy)
                self.assertEqual(sorted(case['binding']), sorted(BINDING_FIELDS))
                self.assertEqual(case['binding'], {'action_id': case['action_id'], 'status': 'unbound',
                                                   'reason': 'not-captured', 'binding_id': None,
                                                   'origin': None})

    def test_a_store_enabled_after_the_fact_backfills_nothing(self):
        """Enabling the policy later must not reach backwards and bind an action that predates it.

        Without this, "we have verification data now" would silently invent provenance for open
        incidents — a binding whose numeric meaning was reviewed after the fact. The positive control is
        in the same database: a NEW action in the same store does bind, so the refusal below is the
        history rule and not a broken capture.
        """
        case = self.bound('late-enable', policy=_AUTO)
        case['store'] = self.open('late-enable', policy=self.policy())
        self.assertEqual(case['store'].get_verification_binding(case['action_id'], READER)['reason'],
                         'not-captured')
        second = self.fire(case['store'], minute=1)
        result, _ = self.propose(case['store'], case['incident_id'], [second['event_id']],
                                 retry_key='second-action')
        bound = case['store'].get_verification_binding(result['action_id'], READER)
        self.assertEqual((bound['status'], bound['reason']), ('bound', 'matched'))
        self.assertRegex(bound['binding_id'], SHA256)

    def test_a_matching_origin_binds_and_the_captured_document_is_the_reviewed_mapping(self):
        """Proof of `bound`/`matched`: the whole normalized mapping plus the event and the targets.

        Every reviewed field is asserted against the policy the operator wrote — the binding is not
        allowed to paraphrase the threshold, drop the artifact pin or re-derive the read scope, because
        those are the three things a later verdict is checked against.
        """
        case = self.bound('matched')
        reviewed = self.mapping()
        self.assertEqual(sorted(case['binding']), sorted(BINDING_FIELDS))
        self.assertEqual(case['binding']['action_id'], case['action_id'])
        self.assertEqual((case['binding']['status'], case['binding']['reason']), ('bound', 'matched'))
        self.assertRegex(case['binding_id'], SHA256)
        self.assertEqual(sorted(case['origin']), sorted((*MAPPING_FIELDS, 'action_targets', 'event_id')))
        self.assertEqual({key: case['origin'][key] for key in MAPPING_FIELDS}, reviewed)
        self.assertIsInstance(case['origin']['threshold'], float)
        self.assertEqual(case['origin']['event_id'], case['event_id'])
        self.assertEqual(case['origin']['action_targets'], [self.host])

    def test_the_binding_id_digests_the_captured_origin_and_not_the_action(self):
        """One origin, two actions: the same digest. Two origins, one action shape: a different digest.

        `binding_id` is how a submitted receipt is tied back to a reviewed check, so it has to be a
        function of the captured origin alone. An id that also covered the action would make the
        comparison in `put_verification` meaningless (two actions on one signal would carry bindings that
        cannot be recognised as one check), and an id that ignored the event would let one binding stand
        in for two different firings of the same rule.
        """
        case = self.bound('digest')
        second, _ = self.propose(case['store'], case['incident_id'], [case['event_id']],
                                 retry_key='other-action')
        other = case['store'].get_verification_binding(second['action_id'], READER)
        self.assertEqual((other['status'], other['binding_id']),
                         ('bound', case['binding_id']))
        again = self.fire(case['store'], minute=1)
        third, _ = self.propose(case['store'], case['incident_id'], [again['event_id']],
                                retry_key='third-action')
        later = case['store'].get_verification_binding(third['action_id'], READER)
        self.assertEqual(later['status'], 'bound')
        self.assertNotEqual(later['binding_id'], case['binding_id'])

    def test_the_same_number_written_two_ways_binds_the_same(self):
        """A threshold normalised once cannot fork a binding on whether it was written `90` or `90.0`.

        A digest that moved with the JSON spelling would make the reviewed check and the recorded check
        different bindings while saying the same thing, and every receipt would then be "not this
        origin's read".
        """
        integer = self.bound('threshold-int', policy=self.policy(mapping=self.mapping(threshold=90)))
        floaten = self.bound('threshold-float', policy=self.policy(mapping=self.mapping(threshold=90.0)))
        self.assertEqual(integer['binding_id'], floaten['binding_id'])
        self.assertEqual(integer['origin']['threshold'], floaten['origin']['threshold'])

    def test_multi_target_is_unbound_and_the_action_keeps_its_own_payload_and_fingerprint(self):
        """Two resources is not one of them plus a guess: no binding, and no change to the client's action.

        The action must survive untouched, so the stored payload and fingerprint are asserted to be
        exactly what `digest`/`canonical` of the caller's request are — the capture may not annotate the
        action it just looked at. A retry of the same request still recognises itself as the same action.
        """
        case = self.bound('multi-target', targets=[self.host, self.service])
        self.assertEqual(case['binding']['status'], 'unbound')
        self.assertEqual(case['binding']['reason'], 'unsupported-targets')
        self.assertIsNone(case['binding']['binding_id'])
        self.assertIsNone(case['binding']['origin'])
        row = next(row for row in case['store'].records('actions', 100) if row['id'] == case['action_id'])
        self.assertEqual(row['payload'], canonical(case['request']))
        self.assertEqual(row['fingerprint'], digest(case['request']))
        self.assertEqual(case['store'].propose_action(case['request'], AGENT, self.gate, now=PROPOSE_NOW),
                         {'action_id': case['action_id'], 'status': 'pending'})
        self.assertEqual(case['store'].get_verification_binding(case['action_id'], READER),
                         case['binding'], 'a retry must not re-decide the binding either')

    def test_only_events_the_action_cites_are_inspected(self):
        """A second matching event in the same incident is not this action's evidence, so it is not read.

        Without the "explicitly cited" rule a second firing of the same rule would turn every action
        that cites one event into `origin-ambiguous`, and the honest-looking answer (refuse to bind)
        would quietly make verification unavailable on any incident that fired twice.
        """
        store = self.open('cited', policy=self.policy())
        first = self.fire(store)
        second = self.fire(store, minute=1)
        result, _ = self.propose(store, first['incident_id'], [first['event_id']])
        binding = store.get_verification_binding(result['action_id'], READER)
        self.assertEqual(binding['reason'], 'matched')
        self.assertEqual(binding['origin']['event_id'], first['event_id'])
        self.assertNotEqual(binding['origin']['event_id'], second['event_id'])

    def test_two_matching_events_are_ambiguity_and_one_cited_twice_is_not(self):
        """More than one distinct matching pair refuses to pick; repeating one citation is still one pair.

        The deduplication matters: `evidence` is a list the caller writes, and counting the same event
        twice would let a client turn a bindable action into an ambiguous one by formatting.
        """
        case = self.bound('ambiguous')
        second = self.fire(case['store'], minute=1)
        both, _ = self.propose(case['store'], case['incident_id'], [case['event_id'], second['event_id']],
                              retry_key='cites-both')
        ambiguous = case['store'].get_verification_binding(both['action_id'], READER)
        self.assertEqual((ambiguous['status'], ambiguous['reason']), ('unbound', 'origin-ambiguous'))
        self.assertIsNone(ambiguous['binding_id'])
        twice, _ = self.propose(case['store'], case['incident_id'], [case['event_id'], case['event_id']],
                                retry_key='cites-twice')
        bound = case['store'].get_verification_binding(twice['action_id'], READER)
        self.assertEqual((bound['status'], bound['reason']), ('bound', 'matched'))
        self.assertEqual(bound['origin']['event_id'], case['event_id'])

    def test_an_event_that_is_not_firing_or_not_reviewed_is_unmatched(self):
        """`origin-unmatched` covers "no mapping selects it" and "that event is not a firing signal".

        A degraded (`unknown`) event is the interesting one: its incident is still open, its selector
        fields match a reviewed mapping exactly, and it is still not evidence that a condition is
        currently firing — so an implementation that matched on the tuple alone would bind a verdict to a
        signal the detector could not evaluate.
        """
        case = self.bound('unmatched', rule_version='4')
        self.assertEqual((case['binding']['status'], case['binding']['reason']),
                         ('unbound', 'origin-unmatched'))
        self.assertIsNone(case['binding']['binding_id'])
        degraded = self.bound('degraded')
        unknown = self.fire(degraded['store'], minute=1, status='unknown')
        result, _ = self.propose(degraded['store'], degraded['incident_id'], [unknown['event_id']],
                                 retry_key='cites-unknown')
        binding = degraded['store'].get_verification_binding(result['action_id'], READER)
        self.assertEqual(binding['reason'], 'origin-unmatched')

    def test_an_unpinned_or_off_origin_reference_does_not_match_a_reviewed_pin(self):
        """A missing pin is not a matching pin: the reference has to carry the reviewed artifact.

        The event's own evidence reference is the only place the pin can come from, and intake admits
        references without a pin, so a capture that matched on the selector tuple and the query type
        would bind a check whose read was never scoped to the reviewed artifact.
        """
        case = self.bound('unpinned', minute=0)
        unpinned = self.fire(case['store'], minute=1,
                            parameters={'resource_id': self.host, 'rule_id': RULE})
        result, _ = self.propose(case['store'], case['incident_id'], [unpinned['event_id']],
                                 retry_key='cites-unpinned')
        self.assertEqual(case['store'].get_verification_binding(result['action_id'], READER)['reason'],
                         'origin-unmatched')
        other = self.fire(case['store'], minute=2, parameters={'resource_id': self.host, 'rule_id': RULE,
                                                             'artifact_sha256': OTHER_PIN})
        second, _ = self.propose(case['store'], case['incident_id'], [other['event_id']],
                                 retry_key='cites-other-pin')
        self.assertEqual(case['store'].get_verification_binding(second['action_id'], READER)['reason'],
                         'origin-unmatched')

    def test_a_retry_keeps_the_binding_captured_under_the_old_policy(self):
        """A restart with a changed mapping must not move the numeric meaning under an open incident.

        The retry path in `propose_action` returns before any capture, and the read must show why that is
        safe: the old action keeps the threshold and artifact that were reviewed when it fired, while a
        new action in the same file is captured against the policy that is current now. Both halves are
        asserted together, because "we preserved the old binding" is only meaningful if the new policy is
        demonstrably live in the same database.
        """
        case = self.bound('restart', policy=self.policy())
        before = case['binding']
        reopened = self.open('restart', policy=self.policy(
            mapping=self.mapping(threshold=50.0, artifact_sha256=OTHER_PIN,
                                 parameters={'resource_id': self.host, 'rule_id': RULE,
                                             'artifact_sha256': OTHER_PIN})))
        self.assertEqual(reopened.propose_action(case['request'], AGENT, self.gate, now=PROPOSE_NOW),
                         {'action_id': case['action_id'], 'status': 'pending'})
        kept = reopened.get_verification_binding(case['action_id'], READER)
        self.assertEqual(kept, before, 'a policy edit may not rebind an action that already bound')
        self.assertEqual(kept['origin']['threshold'], 90.0)
        new_event = self.fire(reopened, minute=1, parameters={'resource_id': self.host, 'rule_id': RULE,
                                                             'artifact_sha256': OTHER_PIN})
        result, _ = self.propose(reopened, case['incident_id'], [new_event['event_id']],
                                 retry_key='new-meaning')
        moved = reopened.get_verification_binding(result['action_id'], READER)
        self.assertEqual((moved['status'], moved['origin']['threshold']), ('bound', 50.0))
        self.assertNotEqual(moved['binding_id'], before['binding_id'])

    def test_lifecycle_steps_never_rebind_or_backfill(self):
        """Decide, claim, outcome and recovery touch no binding, for an unbound or an off action.

        The claim the contract states plainly — "Claim/outcome/recovery never bind, rebind, infer or
        backfill anything" — is worth pinning on the two shapes where guessing is tempting: an action
        whose evidence did not match, and an action proposed while verification was off, each walked all
        the way to a terminal execution and then re-read under an enabled policy.
        """
        unmatched = self.executed(self.bound('no-rebind', rule_version='4'))
        self.assertEqual(unmatched['store'].get_verification_binding(unmatched['action_id'], READER),
                         unmatched['binding'])
        off = self.bound('off-lifecycle', policy=None)
        self.executed(off, outcome='succeeded')
        reopened = self.open('off-lifecycle', policy=self.policy())
        binding = reopened.get_verification_binding(off['action_id'], READER)
        self.assertEqual((binding['status'], binding['reason']), ('unbound', 'not-captured'))
        self.assertEqual(reopened.status()['actions'], {'succeeded': 1})

    def test_an_unknown_action_is_refused_and_a_stray_identifier_is_not_an_action(self):
        """A binding read is about one real action: an absent id is a refusal, not an empty document."""
        case = self.bound('absent')
        self.refused(lambda: case['store'].get_verification_binding(str(uuid.uuid4()), READER))
        self.refused(lambda: case['store'].get_verification_binding('not-a-uuid', READER))
        self.refused(lambda: case['store'].get_verification_binding(None, READER))

    def test_a_binding_read_is_a_fresh_copy_at_every_level(self):
        """A caller that edits what it read must not be able to rewrite the stored provenance.

        The document is nested — `origin` holds a `parameters` dict and an `action_targets` list — and a
        defensive copy of only the outer layer would leave the fields a verdict is checked against
        writable by any reader.
        """
        case = self.bound('copy')
        binding = case['store'].get_verification_binding(case['action_id'], READER)
        binding['status'] = 'unbound'
        binding['reason'] = 'tampered'
        binding['binding_id'] = OTHER_PIN
        binding['origin']['threshold'] = 0.0
        binding['origin']['parameters']['artifact_sha256'] = OTHER_PIN
        binding['origin']['action_targets'].append(self.service)
        self.assertEqual(case['store'].get_verification_binding(case['action_id'], READER),
                         case['binding'])
        self.assertEqual(case['origin']['action_targets'], [self.host])

    def test_the_new_tables_are_not_a_record_query_or_an_audit_category(self):
        """No new list surface and no widened allowlist: the two reads are the whole public door.

        `records()` is the existing capped table reader and its allowlist is a literal; widening it to
        the new tables would be an unreviewed bulk read over verification provenance, and the
        `audit_page` category vocabulary is closed elsewhere in the wave and unchanged here.
        """
        case = self.bound('no-list-surface')
        for table in ('verification_bindings', 'verification_records'):
            self.refused(lambda table=table: case['store'].records(table))
        self.refused(lambda: case['store'].audit_page(category='verification.recorded'))
        self.assertTrue(case['store'].records('audit', 1))


class RecordWriteTests(VerificationFixture):
    """The submitted observation as a statement: its shape, its scope, its authority and its identity.

    A record is the only new write this slice adds, and the interesting inputs are the ones that would
    make a stored verdict mean something other than what the server derived from: a caller supplying its
    own verdict, a receipt of a different read, a sample of a different series, a window the binding
    never reviewed, a clock the caller invented, a future instant, an identity that is not an allowlisted
    producer, and a "retry" whose bytes are not the bytes it claims to repeat.
    """

    def test_a_statement_is_accepted_once_and_the_answer_is_an_id_and_a_flag(self):
        """`{verification_id, created}` is the whole answer, and the stored document is the whole record.

        The fifteen stored fields are asserted as a set because they are the frozen read contract, and
        `action_id`, `origin` and `recorded_by`/`recorded_at` are asserted individually: they are what
        ties a verdict back to the proposal-time binding and to the credential that submitted it.
        """
        case = self.executed(self.bound('accepted'))
        answer = self.put(case)
        self.assertEqual(sorted(answer), ['created', 'verification_id'])
        self.assertIs(answer['created'], True)
        self.assertIsInstance(answer['verification_id'], str)
        case['verification_id'] = answer['verification_id']
        stored = self.stored(case)
        self.assertEqual(sorted(stored), sorted(RECORD_FIELDS))
        self.assertEqual((stored['execution_id'], stored['action_id'], stored['binding_id']),
                         (case['execution_id'], case['action_id'], case['binding_id']))
        self.assertEqual(stored['origin'], case['origin'])
        self.assertEqual(stored['window'], self.window(case))
        self.assertEqual(stored['recorded_by'], VERIFIER.identity)
        self.assertEqual(stored['recorded_at'], utc_text(RECORD_NOW))
        self.assertEqual(stored['verdict'], 'cleared')
        self.assertEqual(len(stored['samples']), 1)
        self.assertEqual(self.stored(case, actor=HUMAN), stored, 'a reader sees the same document')

    def test_the_caller_cannot_send_a_verdict_and_the_six_keys_are_all_required(self):
        """The record vocabulary is six keys: the server's judgement is not an input, in any spelling."""
        case = self.executed(self.bound('keys'))
        for extra in ('verdict', 'reason', 'value', 'sampled_at', 'recorded_by', 'result', 'actor',
                      'action_id', 'window_seconds', 'threshold'):
            document = self.statement(case, **{extra: 'cleared'})
            self.refused(lambda document=document: case['store'].put_verification(document, VERIFIER,
                                                                                 now=RECORD_NOW))
        for field in ('execution_id', 'binding_id', 'window', 'outcome', 'receipt', 'samples'):
            document = self.statement(case)
            del document[field]
            self.refused(lambda document=document: case['store'].put_verification(document, VERIFIER,
                                                                                 now=RECORD_NOW))
        for broken in (None, [], 'record', 0, {'execution_id': case['execution_id']}):
            self.refused(lambda broken=broken: case['store'].put_verification(broken, VERIFIER,
                                                                             now=RECORD_NOW))
        self.assertEqual(self.ops(case['store'], 'verification.recorded'), [])

    def test_the_window_is_the_window_the_binding_reviewed_and_it_is_not_in_the_future(self):
        """Exact duration, half-open bounds, aware stamps, and nothing about a window that has not ended.

        The duration equality is the reason a verifier cannot re-scope a check by submitting a wider
        interval, and the future refusals are the reason a receipt cannot certify its own freshness: an
        answer about a window still in progress is not evidence about the state of anything.
        """
        case = self.executed(self.bound('window'))
        for seconds in (299, 301, 60, 600):
            self.refused(lambda seconds=seconds: self.put(
                case, window=self.window(case, ends_at=RECORD_NOW, seconds=seconds)))
        end = timestamp(self.window(case)['end'])
        flat = {'start': self.window(case)['start'], 'end': self.window(case)['end']}
        self.refused(lambda: self.put(case, window={'start': end.isoformat(), 'end': end.isoformat()},
                                      outcome='unavailable', receipt=None, samples=[]))
        naive = {'start': '2026-09-08T12:06:00', 'end': '2026-09-08T12:11:00'}
        self.refused(lambda: self.put(case, window=naive, outcome='unavailable', receipt=None,
                                      samples=[]))
        accepted = self.put(case, window=flat, outcome='unavailable', receipt=None, samples=[])
        self.assertIs(accepted['created'], True, 'an ordinary bounded window is fileable')
        self.assertEqual(self.put(case, window=flat, outcome='unavailable', receipt=None, samples=[]),
                         {**accepted, 'created': False})
        for window in ({'start': flat['start'], 'end': flat['end'], 'seconds': 300},
                       {'end': flat['end']}, {'start': flat['start']}, 'window',
                       [flat['start'], flat['end']], None):
            self.refused(lambda window=window: self.put(case, window=window, outcome='unavailable',
                                                        receipt=None, samples=[]))
        self.refused(lambda: self.put(case, window=self.window(case, ends_at=RECORD_NOW +
                                                                dt.timedelta(seconds=1))))
        self.refused(lambda: self.put(case, window=self.window(case, ends_at=RECORD_NOW +
                                                                dt.timedelta(hours=6))))

    def test_a_receipt_must_be_the_captured_read_of_the_submitted_window(self):
        """Another read, a wider read or a dead receipt is a refusal for every outcome, never a scoped unknown.

        The receipt is what makes the answer reauthorisable, so a mismatch is not information to file
        under `unknown`: filing it would put a server verdict on top of evidence that was never about
        this check. That holds for `unavailable` and `expired` too — the outcome word does not excuse the
        scope.
        """
        case = self.executed(self.bound('receipt'))
        window = self.window(case)
        origin = case['origin']
        for changes in ({'query_type': 'gatus-result'}, {'query_type': 'metric_threshold'},
                        {'parameters': {'resource_id': origin['resource_id'], 'rule_id': RULE}},
                        {'parameters': {**origin['parameters'], 'sample_id': 'extra'}},
                        {'parameters': {**origin['parameters'], 'resource_id': self.service}},
                        {'window': self.window(case, ends_at=timestamp(window['end']) +
                                             dt.timedelta(seconds=60))},
                        {'expires_at': window['end']},
                        {'expires_at': utc_text(timestamp(window['end']) - dt.timedelta(seconds=1))},
                        {'expires_at': '2026-09-08T12:11:00'},
                        {'sample_count': '1'}, {'truncated': 'false'}):
            for outcome in ('available', 'unavailable', 'expired'):
                rows = self.rows(case, window, [70.0]) if outcome == 'available' else []
                receipt = self.receipt(case, window, **changes)
                with self.subTest(outcome=outcome, **{'change': sorted(changes)}):
                    self.refused(lambda receipt=receipt, outcome=outcome, rows=rows: self.put(
                        case, outcome=outcome, receipt=receipt, samples=rows))
        for tampered in ({**self.receipt(case, window), 'evidence_query_type': 'metric-threshold'},
                         {key: value for key, value in self.receipt(case, window).items()
                          if key != 'truncated'},
                         {key: value for key, value in self.receipt(case, window).items()
                          if key != 'sample_count'},
                         'receipt', [self.receipt(case, window)], 1):
            self.refused(lambda tampered=tampered: self.put(case, receipt=tampered))

    def test_a_null_receipt_is_the_unavailable_answer_and_nothing_else(self):
        """The shape ""nothing came back"" is narrow: unavailable, no receipt, no rows.

        `expired` with no receipt would let a verifier file "the evidence was dead" about evidence it
        never named, and `available` with no receipt is a claim of rows with nothing to check them
        against. Both are refusals; the two unanswered words that do carry a receipt stay fileable, which
        is what keeps an honest "the store did not answer" from being an error the caller has to hide.
        """
        case = self.executed(self.bound('null-receipt'))
        answer = self.put(case, outcome='unavailable', receipt=None, samples=[],
                         window=self.window(case, ends_at=RECORD_NOW - dt.timedelta(minutes=3)))
        self.assertIs(answer['created'], True,
                      'an honest "the store did not answer" is a statement, not an error')
        self.refused(lambda: self.put(case, outcome='available', receipt=None))
        self.refused(lambda: self.put(case, outcome='unavailable', receipt=None,
                                      samples=self.rows(case, self.window(case), [70.0])))
        self.refused(lambda: self.put(case, outcome='expired', receipt=None, samples=[]))
        self.refused(lambda: self.put(case, outcome='expired',
                                      receipt=self.receipt(case, self.window(case)),
                                      samples=self.rows(case, self.window(case), [70.0])))
        self.refused(lambda: self.put(case, outcome='unavailable',
                                      samples=self.rows(case, self.window(case), [70.0])))

    def test_rows_are_the_captured_series_inside_the_half_open_window(self):
        """A row of another series or resource, or stamped outside the window, is a refusal.

        Rows are the deciding evidence, so a mismatched row is not "an unusable sample" — filing it
        would put a server verdict on a number that is not the metric that paged. The half-open bound is
        asserted from both sides: at `start` a row belongs, at `end` it does not, because the window a
        receipt describes is ``[start, end)`` everywhere else in this platform.
        """
        case = self.executed(self.bound('rows'))
        window = self.window(case)
        inside = utc_text(timestamp(window['start']))
        origin = case['origin']
        for row in ({'resource_id': self.service, 'metric_name': origin['metric_name'],
                     'observed_at': inside, 'value': 70.0},
                    {'resource_id': origin['resource_id'], 'metric_name': 'other_series',
                     'observed_at': inside, 'value': 70.0},
                    {'resource_id': origin['resource_id'], 'metric_name': origin['metric_name'],
                     'observed_at': inside, 'value': 70.0, 'labels': {}},
                    {'resource_id': origin['resource_id'], 'metric_name': origin['metric_name'],
                     'observed_at': inside},
                    {'resource_id': origin['resource_id'], 'metric_name': origin['metric_name'],
                     'observed_at': window['end'], 'value': 70.0},
                    {'resource_id': origin['resource_id'], 'metric_name': origin['metric_name'],
                     'observed_at': utc_text(timestamp(window['start']) - dt.timedelta(seconds=1)),
                     'value': 70.0},
                    {'resource_id': origin['resource_id'], 'metric_name': origin['metric_name'],
                     'observed_at': '2026-09-08 12:06:00', 'value': 70.0},
                    {'resource_id': origin['resource_id'], 'metric_name': origin['metric_name'],
                     'observed_at': utc_text(RECORD_NOW + dt.timedelta(hours=6)), 'value': 70.0}):
            self.refused(lambda row=row: self.put(
                case, samples=[row], receipt=self.receipt(case, window, count=1)))
        for samples in ('rows', {'resource_id': origin['resource_id']}, None, [None], ['70'],
                       [[70.0]]):
            self.refused(lambda samples=samples: self.put(
                case, samples=samples, receipt=self.receipt(case, window, count=0)))
        self.assertIs(self.put(case, window=window, receipt=self.receipt(case, window),
                              samples=self.rows(case, window, [70.0], at=inside))['created'], True,
                      'a row at the half-open start belongs to the window')

    def test_the_statement_is_bounded_in_rows_counts_numbers_and_bytes(self):
        """Twenty rows, ten thousand claimed rows, finite non-bool values, 32 KiB: bounds, not opinions.

        `sample_count` is wider than a receipt from the facade on purpose (a verifier may cite a read
        the store bounded elsewhere), and `value` is refused as `True` for the same reason a policy
        refuses it: a boolean standing in for a measurement is the oldest way to make a threshold check
        read as a pass.
        """
        case = self.executed(self.bound('bounds'))
        window = self.window(case)
        origin = case['origin']
        earlier = self.window(case, ends_at=RECORD_NOW - dt.timedelta(minutes=1))
        for count in (10001, -1, True, '1', None, 2 ** 63):
            self.refused(lambda count=count: self.put(
                case, window=earlier, samples=[],
                receipt=self.receipt(case, earlier, count=0, sample_count=count)))
        self.refused(lambda: self.put(case, samples=self.rows(case, window, [70.0, 71.0]),
                                      receipt=self.receipt(case, window, count=1)))
        for value in (True, False, '70', None, float('nan'), float('inf'), 10 ** 400, [70.0]):
            self.refused(lambda value=value: self.put(
                case, samples=[{'resource_id': origin['resource_id'], 'metric_name': origin['metric_name'],
                                  'observed_at': window['start'], 'value': value}],
                receipt=self.receipt(case, window, count=1)))
        for truncated in ('true', 1, None, 0.0):
            self.refused(lambda truncated=truncated: self.put(
                case, receipt=self.receipt(case, window, truncated=truncated)))
        self.refused(lambda: self.put(case, samples=self.rows(case, window, [70.0] * 21),
                                      receipt=self.receipt(case, window, count=21)))
        self.assertIs(self.put(case, samples=self.rows(case, window, [70.0] * 20),
                              receipt=self.receipt(case, window, count=20))['created'], True,
                      'twenty rows is the bound, so it has to fit')

    def test_a_statement_larger_than_the_document_cap_is_refused_without_a_trace(self):
        """An oversized document is refused, unwritten and unaudited, and the sentence does not carry it.

        The byte cap and the field bounds overlap on purpose — every field that could hold forty
        thousand characters is also a label, a UUID or a number — so what is observable, and what this
        pins, is that an oversized payload cannot become a stored record, cannot become an audit row, and
        cannot be echoed back at the caller who sent it.
        """
        case = self.executed(self.bound('oversized'))
        window = self.window(case)
        origin = case['origin']
        sentinel = 'y' * 40000
        bloated = self.statement(case, receipt=self.receipt(case, window, parameters={
            **origin['parameters'], 'rule_id': sentinel}))
        self.assertGreater(len(canonical(bloated).encode()), 32768)
        self.refused(lambda: case['store'].put_verification(bloated, VERIFIER, now=RECORD_NOW),
                     sentinel[:64])
        self.assertEqual(self.ops(case['store'], 'verification.recorded'), [])
        rows = [row for row in case['store'].records('audit', 100) if sentinel[:64] in str(row)]
        self.assertEqual(rows, [], 'a refused payload may not reach the audit log either')
        answer = self.put(case)
        case['verification_id'] = answer['verification_id']
        self.assertIs(answer['created'], True, 'the refusal must not wedge the store')

    def test_only_a_currently_allowlisted_producer_may_write(self):
        """A verifier is a role `producer` whose identity is in the current policy. Nothing less, nothing more.

        A runner, a human, a proposer, a reader, a summary credential and an unlisted producer are all
        refused, and so is the executor identity *placed in the allowlist* — the role gate is not
        satisfied by naming a verifier in a body or in a policy the caller does not hold. Positive
        control: both configured verifiers may write, which is what makes the refusals a firewall and not
        a broken door.
        """
        case = self.executed(self.bound('authority'))
        for actor in (READER, HUMAN, AGENT, RUNNER, SUMMARY, UNLISTED, Actor(VERIFIER.identity, 'human'),
                      Actor(VERIFIER.identity, 'executor'), Actor(VERIFIER.identity, 'proposer'),
                      Actor(VERIFIER.identity, 'reader'), Actor(VERIFIER.identity, 'producer '),
                      Actor('', 'producer'), Actor(None, 'producer'), 'producer', None,
                      {'identity': VERIFIER.identity, 'role': 'producer'}):
            with self.subTest(repr(actor)):
                self.refused(lambda actor=actor: self.put(case, actor=actor))
        self.assertEqual(self.ops(case['store'], 'verification.recorded'), [])
        for position, actor in enumerate((VERIFIER, SECOND_VERIFIER)):
            with self.subTest(writes=actor.identity):
                answer = self.put(case, actor=actor, window=self.window(
                    case, ends_at=RECORD_NOW - dt.timedelta(minutes=2 + position)))
                self.assertIs(answer['created'], True)
        pinned = self.executed(self.bound('verifier-is-not-a-role',
                                          policy=self.policy(verifiers=[RUNNER])))
        self.refused(lambda: self.put(pinned, actor=RUNNER))

    def test_revoking_a_verifier_stops_writes_without_touching_what_was_written(self):
        """Current authority gates writes: a replay by a revoked verifier is still refused.

        The retry rule says authority is checked before a retry is accepted, so "I wrote this yesterday"
        is not a capability today. What is *not* revoked is the record: it stays readable and unchanged,
        because immutable history and live authority are different questions.
        """
        case = self.executed(self.bound('revoked'))
        answer = self.put(case)
        case['verification_id'] = answer['verification_id']
        before = self.stored(case)
        revoked = self.open('revoked', policy=self.policy(verifiers=[SECOND_VERIFIER]))
        document = self.statement(case)
        self.refused(lambda: revoked.put_verification(document, VERIFIER, now=RECORD_NOW))
        self.refused(lambda: revoked.put_verification(self.statement(
            case, window=self.window(case, ends_at=RECORD_NOW - dt.timedelta(minutes=1))), VERIFIER,
            now=RECORD_NOW))
        self.refused(lambda: revoked.get_verification(before['verification_id'], VERIFIER))
        self.assertEqual(revoked.get_verification(before['verification_id'], READER), before)
        self.assertIs(revoked.put_verification(document, SECOND_VERIFIER, now=RECORD_NOW)['created'],
                      False, 'an exact replay by a still-listed verifier is the same check')

    def test_the_server_clock_is_the_only_clock_and_it_must_be_aware(self):
        """A naive or non-clock `now` is a refusal, and the real UTC clock is what happens by default.

        The receipt cannot say when it was judged — that is the same self-certifying-freshness hole the
        existing verification unit refuses — so the default has to be a real aware clock. The window here
        is built from the actual instant rather than a fixture constant, which is the only way to assert
        "no clock named still works" without a fake clock to hold.
        """
        case = self.executed(self.bound('clock'))
        for now in (dt.datetime(2026, 9, 8, 12, 20), '2026-09-08T12:20:00Z', 1757334000,
                    object(), PROPOSE_NOW.isoformat()):
            with self.subTest(repr(now)):
                self.refused(lambda now=now: self.put(case, now=now))
        real = dt.datetime.now(dt.timezone.utc)
        live = {'start': utc_text(real - dt.timedelta(seconds=420)),
                'end': utc_text(real - dt.timedelta(seconds=120))}
        answer = case['store'].put_verification(self.statement(
            case, window=live, samples=self.rows(case, live, [70.0], at=live['start']),
            receipt=self.receipt(case, live)), VERIFIER)
        self.assertIs(answer['created'], True)
        self.assertIn(case['store'].get_verification(answer['verification_id'], READER)['verdict'],
                      ('cleared', 'not_cleared', 'unknown'))

    def test_a_statement_needs_a_finished_execution_of_the_action_that_bound(self):
        """Executing is refused; succeeded and failed are proved; unknown is stored as unknown.

        Four states, four answers, one reason each: a run that may still be in flight cannot be judged
        (`executing` is refused outright, `unknown` is filed as `execution-boundary-unknown` because it
        may still be running), and an action with no binding has nothing for a receipt to match, so the
        store refuses rather than inventing a scope to judge against.
        """
        running = self.executed(self.bound('executing'), outcome=None)
        self.refused(lambda: self.put(running))
        absent = self.executed(self.bound('absent-execution'))
        absent['execution_id'] = str(uuid.uuid4())
        self.refused(lambda: self.put(absent))
        unbound = self.executed(self.bound('unbound-execution', rule_version='4'))
        self.refused(lambda: self.put(unbound, binding_id=OTHER_PIN))
        self.refused(lambda: self.put(unbound, binding_id=None))
        off = self.executed(self.bound('off-execution', policy=None))
        self.refused(lambda: self.put(off, binding_id=PIN))
        for outcome in ('succeeded', 'failed'):
            case = self.executed(self.bound(f'terminal-{outcome}'), outcome=outcome)
            answer = self.put(case)
            case['verification_id'] = answer['verification_id']
            self.assertIs(answer['created'], True, f'a {outcome} run is a proved terminal state')
            self.assertEqual(self.stored(case)['verdict'], 'cleared')
        interrupted = self.executed(self.bound('interrupted'), outcome=None)
        self.assertEqual(interrupted['store'].recover_executions(now=TERMINAL), 1)
        interrupted['terminal'] = TERMINAL
        answer = self.put(interrupted, outcome='unavailable')
        interrupted['verification_id'] = answer['verification_id']
        stored = self.stored(interrupted)
        self.assertEqual((stored['verdict'], stored['reason']),
                         ('unknown', 'execution-boundary-unknown'))
        self.assertEqual(interrupted['store'].status()['actions'], {'unknown': 1})

    def test_an_identical_replay_from_another_verifier_is_the_same_check(self):
        """The logical identity excludes the submitting identity: two credentials, one stored statement.

        Two verifiers that both performed the same read must not fork the record into two rows, and the
        row must keep naming whoever recorded it first — `created=False` is the answer that says "we
        already had this", and `recorded_by` is the answer to "who said it".
        """
        case = self.executed(self.bound('replay'))
        document = self.statement(case)
        first = case['store'].put_verification(document, VERIFIER, now=RECORD_NOW)
        replay = case['store'].put_verification(copy.deepcopy(document), SECOND_VERIFIER, now=RECORD_NOW)
        self.assertEqual(replay, {**first, 'created': False})
        self.assertEqual(self.stored(case, first['verification_id'])['recorded_by'], VERIFIER.identity)
        self.assertEqual(len(self.ops(case['store'], 'verification.recorded')), 1,
                         'a duplicate attempt adds no audit row')
        again = case['store'].get_verification(first['verification_id'], READER)
        self.assertEqual(again['samples'], document['samples'])

    def test_changed_content_under_the_same_identity_is_a_conflict(self):
        """Same execution, binding and window with different bytes is a conflict, not a second opinion.

        Every mutation here is one a sloppy client could send by accident — a re-read that landed on a
        different page, an outcome word changed on retry, a receipt whose count moved — and the answer
        must be a refusal that leaves the first statement standing. A store that overwrote, or that
        filed the second claim alongside the first, would let a verdict be revised by whoever spoke last.
        """
        case = self.executed(self.bound('conflict'))
        answer = self.put(case)
        case['verification_id'] = answer['verification_id']
        before = self.stored(case)
        window = self.window(case)
        changes = {'a different sample value': self.statement(
                       case, samples=self.rows(case, window, [150.0],
                                               at=utc_text(timestamp(window['end']) -
                                                         dt.timedelta(seconds=90)))),
                   'a different outcome word': self.statement(
                       case, outcome='unavailable', receipt=None, samples=[]),
                   'a receipt that claims more rows': self.statement(
                       case, receipt=self.receipt(case, window, count=1, sample_count=7)),
                   'a receipt that is expiring differently': self.statement(
                       case, receipt=self.receipt(case, window, count=1,
                                                  expires_at=utc_text(timestamp(window['end']) +
                                                                      dt.timedelta(days=1))))}
        for label, document in changes.items():
            with self.subTest(case=label):
                self.refused(lambda document=document: case['store'].put_verification(
                    document, VERIFIER, now=RECORD_NOW))
        self.assertEqual(self.stored(case), before, 'a conflict may not rewrite the first statement')
        self.assertEqual(len(self.ops(case['store'], 'verification.recorded')), 1)
        later = self.put(case, window=self.window(case, ends_at=RECORD_NOW - dt.timedelta(minutes=1)))
        self.assertIs(later['created'], True, 'a later window is a different check, not a conflict')

    def test_an_already_accepted_statement_is_not_regraded_by_a_later_clock_or_status(self):
        """Idempotence is not re-judging: a replay answers with the record, whatever the world looks like now.

        Both halves of the rule are the ones an implementation gets wrong by "helpfully" re-running the
        judgement: an evidence expiry that arrived since the first write, and an execution that was
        reconciled after it. Re-grading either would rewrite history with a clock the original submitter
        never had.
        """
        case = self.executed(self.bound('regrade'), outcome=None)
        case['store'].recover_executions(now=TERMINAL)
        case['terminal'] = TERMINAL
        unknown_window = self.window(case)
        answer = self.put(case, window=unknown_window, outcome='unavailable')
        case['verification_id'] = answer['verification_id']
        unknown = self.stored(case)
        self.assertEqual(unknown['reason'], 'execution-boundary-unknown')
        case['store'].execution_outcome(case['execution_id'], 'failed', HUMAN, now=TERMINAL)
        replay = case['store'].put_verification(self.statement(
            case, window=unknown_window, outcome='unavailable'), VERIFIER,
            now=RECORD_NOW + dt.timedelta(days=2))
        self.assertEqual(replay, {**answer, 'created': False})
        self.assertEqual(self.stored(case), unknown, 'a reconciled execution may not re-grade a verdict')
        expiring = self.window(case, ends_at=RECORD_NOW - dt.timedelta(minutes=5))
        live = self.receipt(case, expiring, count=1,
                            expires_at=utc_text(RECORD_NOW + dt.timedelta(seconds=60)))
        rows = self.rows(case, expiring, [150.0],
                         at=utc_text(timestamp(expiring['end']) - dt.timedelta(seconds=30)))
        second = self.put(case, window=expiring, receipt=live, samples=rows)
        self.assertEqual(self.stored(case, second['verification_id'])['verdict'], 'not_cleared',
                         'the evidence is live at the instant it is judged, and says the signal is there')
        replayed = self.put(case, window=expiring, receipt=live, samples=rows,
                            now=RECORD_NOW + dt.timedelta(hours=6))
        self.assertEqual(replayed, {**second, 'created': False})
        self.assertEqual(self.stored(case, second['verification_id'])['verdict'], 'not_cleared',
                         'evidence that died since then must not turn a filed verdict into an unknown')

    def test_a_window_spelled_differently_is_the_same_check(self):
        """Normalisation happens before identity: `Z`, `+00:00` and `+02:00` are one interval.

        Stored bounds are the one UTC text form everywhere in this repository, and the logical identity
        is built from normalised values — so a client that resends the same window in another spelling is
        retrying, and a store that compared strings would file the same observation twice under two
        ids, which is how one check grows into two verdicts.
        """
        case = self.executed(self.bound('spelling'))
        window = self.window(case)
        answer = self.put(case, window=window)
        shifted = {'start': timestamp(window['start']).astimezone(dt.timezone(
                       dt.timedelta(minutes=120))).isoformat(),
                   'end': timestamp(window['end']).astimezone(dt.timezone(
                       dt.timedelta(minutes=120))).isoformat()}
        replay = self.put(case, window=shifted,
                          receipt=self.receipt(case, shifted, count=1),
                          samples=self.rows(case, shifted, [70.0],
                                            at=timestamp(self.rows(case, window, [70.0])[0][
                                                'observed_at']).astimezone(
                                                dt.timezone(dt.timedelta(minutes=120))).isoformat()))
        self.assertEqual(replay, {**answer, 'created': False})
        self.assertEqual(self.stored(case, answer['verification_id'])['window'], window)

    def test_the_sixty_fourth_statement_lands_and_the_sixty_fifth_new_window_does_not(self):
        """A bounded number of first writes per execution, with exact retries still allowed at the cap.

        Sixty-four distinct windows are accepted and stored; the sixty-fifth new window is refused while
        the store keeps accepting retries of what it already holds. The cap is what stops a caller from
        growing one execution's history at will, and the retry rule is what stops the cap from becoming
        a way to lose an accepted statement.
        """
        case = self.executed(self.bound('cap'))
        issued = []
        for offset in range(64):
            window = self.window(case, ends_at=RECORD_NOW - dt.timedelta(seconds=WINDOW_SECONDS * offset))
            answer = self.put(case, window=window, outcome='unavailable', receipt=None, samples=[])
            self.assertIs(answer['created'], True, f'statement {offset} is a first write')
            issued.append(answer['verification_id'])
        self.assertEqual(len(set(issued)), 64, 'one id per distinct window')
        overflow = self.window(case, ends_at=RECORD_NOW - dt.timedelta(seconds=WINDOW_SECONDS * 64))
        self.refused(lambda: self.put(case, window=overflow, outcome='unavailable', receipt=None,
                                      samples=[]))
        retry = self.put(case, window=self.window(case, ends_at=RECORD_NOW - dt.timedelta(
            seconds=WINDOW_SECONDS * 63)), outcome='unavailable', receipt=None, samples=[])
        self.assertEqual(retry, {'verification_id': issued[63], 'created': False})
        self.assertEqual(len(self.ops(case['store'], 'verification.recorded')), 64)


class JudgementTests(VerificationFixture):
    """The derived verdict: one precedence, the newest instant, and what a verdict may not touch.

    The server judges, so there are two ways to get that wrong and this class is built around both. Too
    eager: a partial, stale, pre-terminal or unanswered read reported as `cleared`. Too lazy: a refusal to
    store an honest `unknown`, or a verdict that reaches out and changes the incident, the action or the
    execution it describes. The precedence order is asserted where several of its clauses are true at
    once, because "which reason do you report" is the question an operator reading an incident at three
    in the morning actually asks, and a reordered list still answers `unknown` while saying something
    false about why.
    """

    def graded(self, case, answer, statement, verdict, reason) -> dict:
        """Assert one accepted statement's judgement and that the submitted evidence came back through.

        Preserving the receipt and the rows is not decoration: an `unknown` that discarded them would be
        indistinguishable from a store that never received the message, and the value of the record is
        that a later reader can see what was looked at and found unusable.
        """
        self.assertIs(answer['created'], True)
        case['verification_id'] = answer['verification_id']
        stored = self.stored(case)
        self.assertEqual((stored['verdict'], stored['reason']), (verdict, reason))
        self.assertEqual(stored['samples'], statement['samples'])
        self.assertEqual(stored['receipt'], statement['receipt'])
        self.assertEqual(stored['outcome'], statement['outcome'])
        return stored

    def submit(self, case, *, ends_at=None, outcome='available', count=1, values=(70.0,), at=None,
               window=None, receipt=_AUTO, **receipt_changes):
        """Build one statement over the captured origin and put it, returning the pair to assert on.

        A receipt is built whenever the outcome is `available` or the test asked for a change in one,
        which is how an `unavailable` answer can still carry the truncated receipt that makes the
        precedence question worth asking.
        """
        window = window or self.window(case, ends_at=ends_at)
        rows = [] if not values else self.rows(case, window, list(values), at=at)
        if receipt is _AUTO:
            receipt = (self.receipt(case, window, count=count, **receipt_changes)
                       if outcome == 'available' or receipt_changes else None)
        statement = self.statement(case, window=window, outcome=outcome, receipt=receipt, samples=rows)
        return statement, case['store'].put_verification(statement, VERIFIER, now=RECORD_NOW)

    def test_the_precedence_answers_the_earliest_true_reason(self):
        """Nine clauses, each tested with the clauses after it also true."""
        case = self.executed(self.bound('precedence'))
        ends = [TERMINAL + dt.timedelta(minutes=6 + index) for index in range(8)]

        with self.subTest(clause='2 pre-execution-window, also truncated and empty'):
            statement, answer = self.submit(
                case, window={'start': utc_text(TERMINAL - dt.timedelta(seconds=600)),
                              'end': utc_text(TERMINAL - dt.timedelta(seconds=300))},
                count=5, values=(), truncated=True)
            self.graded(case, answer, statement, 'unknown', 'pre-execution-window')
        with self.subTest(clause='3 store-unanswered, on a truncated receipt'):
            statement, answer = self.submit(case, ends_at=ends[0], outcome='unavailable', values=(),
                                            count=0, truncated=True)
            self.graded(case, answer, statement, 'unknown', 'store-unanswered')
        with self.subTest(clause='3 an expired verdict answer carries no rows either'):
            statement, answer = self.submit(case, ends_at=ends[1], outcome='expired', values=(),
                                            count=0, truncated=True)
            self.graded(case, answer, statement, 'unknown', 'store-unanswered')
        with self.subTest(clause='4 evidence-expired, also truncated and short of rows'):
            window = self.window(case, ends_at=ends[2])
            receipt = dict(self.receipt(case, window, count=9, truncated=True),
                           expires_at=utc_text(RECORD_NOW - dt.timedelta(seconds=1)))
            statement = self.statement(case, window=window, receipt=receipt, samples=[])
            answer = case['store'].put_verification(statement, VERIFIER, now=RECORD_NOW)
            self.graded(case, answer, statement, 'unknown', 'evidence-expired')
        with self.subTest(clause='5 evidence-truncated, also short of rows'):
            statement, answer = self.submit(case, ends_at=ends[3], count=9, values=(), truncated=True)
            self.graded(case, answer, statement, 'unknown', 'evidence-truncated')
        with self.subTest(clause='6 evidence-incomplete, an excerpt that is also empty'):
            statement, answer = self.submit(case, ends_at=ends[4], count=3, values=())
            self.graded(case, answer, statement, 'unknown', 'evidence-incomplete')
        with self.subTest(clause='7 window-empty'):
            statement, answer = self.submit(case, ends_at=ends[5], count=0, values=())
            self.graded(case, answer, statement, 'unknown', 'window-empty')
        with self.subTest(clause='8 pre-execution-sample, a violating value at the terminal instant'):
            statement, answer = self.submit(
                case, ends_at=TERMINAL + dt.timedelta(seconds=WINDOW_SECONDS), values=(500.0,),
                at=utc_text(TERMINAL))
            self.assertEqual(statement['window']['start'], utc_text(TERMINAL),
                             'a window that starts at the terminal instant is allowed: equality is not '
                             'staleness')
            self.graded(case, answer, statement, 'unknown', 'pre-execution-sample')
        with self.subTest(clause='9 any newest value failing is not_cleared'):
            statement, answer = self.submit(case, ends_at=ends[6], count=2, values=(85.0, 120.0))
            self.graded(case, answer, statement, 'not_cleared', 'comparison-failed')
        with self.subTest(clause='9 every newest value satisfying is cleared'):
            statement, answer = self.submit(case, ends_at=ends[7], count=2, values=(85.0, 80.0))
            self.graded(case, answer, statement, 'cleared', 'comparison-satisfied')

    def test_an_unknown_execution_is_stored_as_unknown_and_stays_that_way(self):
        """Rule 1 outranks everything, and reconciling the run afterwards does not rewrite the record."""
        case = self.executed(self.bound('boundary'), outcome=None)
        case['store'].recover_executions(now=TERMINAL)
        case['terminal'] = TERMINAL
        statement, answer = self.submit(case, outcome='unavailable', values=(), count=0,
                                        ends_at=RECORD_NOW - dt.timedelta(minutes=1))
        self.graded(case, answer, statement, 'unknown', 'execution-boundary-unknown')
        self.assertEqual(case['store'].execution_outcome(case['execution_id'], 'succeeded', HUMAN,
                                                        now=RECORD_NOW), {'status': 'succeeded'},
                         "the runner's word stays the execution's word")
        self.assertEqual(self.stored(case)['verdict'], 'unknown', 'and it does not rewrite the verdict')

    def test_the_deciding_value_is_the_one_least_favourable_to_cleared(self):
        """The newest instant decides, all of it, and the filed value is the worst point that instant holds.

        `lt` is decided by the largest point, so a healthy sample cannot rescue a still-firing host, and
        the filed value is that largest one — the number a reader needs in order to distrust the answer.
        Averaging or taking the first of several newest points would hide a violation. The second half is
        the other direction: a firing hour followed by a healthy minute is a recovery, and older rows are
        context rather than the answer.
        """
        case = self.executed(self.bound('worst'))
        window = self.window(case, ends_at=RECORD_NOW - dt.timedelta(minutes=1))
        late = utc_text(timestamp(window['end']) - dt.timedelta(seconds=30))
        statement, answer = self.submit(case, window=window, count=2, values=(85.0, 120.0), at=late)
        stored = self.graded(case, answer, statement, 'not_cleared', 'comparison-failed')
        self.assertEqual((stored['value'], stored['sampled_at']), (120.0, late))

        newer = self.window(case, ends_at=RECORD_NOW)
        early = utc_text(timestamp(newer['start']) + dt.timedelta(seconds=30))
        statement = self.statement(
            case, window=newer,
            samples=self.rows(case, newer, [500.0], at=early) +
            self.rows(case, newer, [10.0], at=late),
            receipt=self.receipt(case, newer, count=2))
        answer = case['store'].put_verification(statement, VERIFIER, now=RECORD_NOW)
        stored = self.graded(case, answer, statement, 'cleared', 'comparison-satisfied')
        self.assertEqual((stored['value'], stored['sampled_at']), (10.0, late))

    def test_each_reviewed_comparison_is_judged_against_the_captured_threshold(self):
        """Five directions, hand-answered: a mapping read backwards is a recovery that never happened.

        Each direction gets one satisfying and one violating statement, with the expected answer spelled
        out here rather than recomputed from the module's own comparison table — arithmetic shared with
        the code under test would grade itself. `eq` and the `ge`/`gt` pair are the two directions a
        reversed implementation gets wrong in opposite ways.
        """
        matrix = (('lt', 90.0, 85.0, 95.0), ('le', 90.0, 90.0, 90.5), ('gt', 90.0, 95.0, 85.0),
                  ('ge', 90.0, 90.0, 89.5), ('eq', 90.0, 90.0, 91.0))
        for position, (comparison, threshold, passing, failing) in enumerate(matrix):
            mapping = self.mapping(comparison=comparison, threshold=threshold)
            case = self.executed(self.bound(f'comparison-{position}', policy=self.policy(mapping=mapping)))
            self.assertEqual(case['origin']['comparison'], comparison)
            for value, verdict in ((passing, 'cleared'), (failing, 'not_cleared')):
                ends_at = RECORD_NOW - dt.timedelta(minutes=position * 2 +
                                                    (0 if verdict == 'cleared' else 1))
                statement, answer = self.submit(case, ends_at=ends_at, count=1, values=(value,))
                with self.subTest(comparison=comparison, verdict=verdict):
                    stored = self.graded(case, answer, statement, verdict,
                                         'comparison-satisfied' if verdict == 'cleared'
                                         else 'comparison-failed')
                    self.assertEqual(stored['value'], float(value))

    def test_a_succeeded_execution_still_firing_is_not_cleared_and_closes_nothing(self):
        """The remediation invariants invariant on durable rows: the verdict is stored, the incident does not move.

        A runner that finished cleanly, a read that answered completely, and a metric still outside its
        threshold: the answer is `not_cleared`, and the incident is exactly where it was — status counts,
        incident rows, outbox rows and the action's own status all unchanged. The same assertion runs on
        a `cleared` verdict, because a storage slice that resolved an incident on a good reading would be
        inventing lifecycle that belongs to intake.
        """
        case = self.executed(self.bound('still-firing'))
        before = case['store'].status()
        outbox = case['store'].records('outbox', 10)
        incidents = case['store'].records('incidents', 10)
        statement, answer = self.submit(case, ends_at=RECORD_NOW - dt.timedelta(minutes=5), count=1,
                                        values=(150.0,))
        stored = self.graded(case, answer, statement, 'not_cleared', 'comparison-failed')
        self.assertEqual(stored['value'], 150.0)
        self.assertEqual(case['store'].status(), before, 'a verdict moved nothing')
        self.assertEqual(case['store'].records('incidents', 10), incidents)
        self.assertEqual(case['store'].records('outbox', 10), outbox)
        self.assertEqual(self.action_row(case['store'], case['action_id'])['status'], 'succeeded',
                         "the runner's outcome is still the action's status")
        self.assertEqual(self.execution_row(case['store'], case['execution_id'])['status'], 'succeeded')
        self.assertEqual(case['store'].status()['incidents'], {'open': 1})
        self.assertEqual([row['operation'] for row in case['store'].records('audit', 1)],
                         ['verification.recorded'], 'the only durable addition is one audit row')

        recovered = self.executed(self.bound('cleared-closes-nothing'))
        answer = self.put(recovered)
        recovered['verification_id'] = answer['verification_id']
        self.assertEqual(self.stored(recovered)['verdict'], 'cleared')
        self.assertEqual(recovered['store'].status()['incidents'], {'open': 1},
                         'a clearance is not a resolved event')
        self.assertEqual(self.action_row(recovered['store'], recovered['action_id'])['status'],
                         'succeeded')

    def test_a_stored_verdict_survives_the_clock_the_expiry_and_the_policy_change(self):
        """No pruning, no implicit expiry deletion, no re-grading from a later world.

        Read after the incident resolved and after a restart onto a different mapping, the record is
        field-for-field what it was. Verifiers are trusted for whether the read happened and how complete
        it was, and the vocabulary says so by omission: the stored document carries what the verifier
        claimed and what this server derived, and there is no field that attests a remote read took place.
        """
        case = self.executed(self.bound('longevity'))
        answer = self.put(case)
        case['verification_id'] = answer['verification_id']
        before = self.stored(case)
        self.assertEqual(sorted(before), sorted(RECORD_FIELDS),
                         'the read vocabulary is the frozen one, attestation included')
        self.fire(case['store'], minute=25, status='resolved')
        restarted = self.open('longevity', policy=self.policy(mapping=self.mapping(threshold=0.5,
                                                                                  comparison='gt')))
        self.assertEqual(restarted.get_verification(before['verification_id'], HUMAN), before)
        self.assertEqual(restarted.get_verification_binding(case['action_id'],
                                                          READER)['binding_id'], case['binding_id'])
        self.assertEqual(restarted.status()['incidents'], {'resolved': 1})

    def test_a_statement_that_is_entirely_absent_reads_as_nothing(self):
        """A single-object read of an id nobody issued is `None`, not an error and not an empty record."""
        case = self.executed(self.bound('absent-record'))
        self.assertIsNone(case['store'].get_verification(digest(str(uuid.uuid4())), READER))
        self.refused(lambda: case['store'].get_verification(None, READER))
        self.refused(lambda: case['store'].get_verification('not-an-id', READER))

    def action_row(self, store, action_id) -> dict:
        return next(row for row in store.records('actions', 100) if row['id'] == action_id)

    def execution_row(self, store, execution_id) -> dict:
        return next(row for row in store.records('executions', 100) if row['id'] == execution_id)


class ReadAuthorityTests(VerificationFixture):
    """Who may read a binding and a record, and what they get hold of when they do.

    The contract reuses the platform's existing roles rather than minting a verifier credential, which
    makes the read gate the interesting half: a producer is trusted to *write* only while it is named in
    the current policy, and everything that can already read platform state can read this state, because
    an operator who cannot see the provenance behind a verdict cannot act on it. A malformed actor is
    refused ahead of the database, which is the same ordering the rest of the store keeps: an
    unauthorised credential is not entitled to learn whether the row exists.
    """

    def test_the_read_roles_are_the_existing_ones_and_a_producer_needs_the_current_allowlist(self):
        """Reader, human, proposer and executor read; an unlisted producer and a summary credential do not."""
        case = self.executed(self.bound('read-authority'))
        answer = self.put(case)
        case['verification_id'] = answer['verification_id']
        for actor in (READER, HUMAN, AGENT, RUNNER, VERIFIER, SECOND_VERIFIER):
            with self.subTest(reads=actor.identity):
                self.assertEqual(case['store'].get_verification(case['verification_id'], actor)['verdict'],
                                 'cleared')
                self.assertEqual(case['store'].get_verification_binding(case['action_id'],
                                                                        actor)['binding_id'],
                                 case['binding_id'])
        for actor in (UNLISTED, SUMMARY, Actor('verify-worker', 'reader '), Actor('', 'reader'),
                      Actor(None, 'reader'), 'reader', None, {'identity': 'reader-1', 'role': 'reader'}):
            with self.subTest(refused=repr(actor)):
                self.refused(lambda actor=actor: case['store'].get_verification(case['verification_id'],
                                                                                actor))
                self.refused(lambda actor=actor: case['store'].get_verification_binding(case['action_id'],
                                                                                        actor))
        revoked = self.open('read-authority', policy=self.policy(verifiers=[SECOND_VERIFIER]))
        self.refused(lambda: revoked.get_verification(case['verification_id'], VERIFIER))
        self.assertEqual(revoked.get_verification(case['verification_id'], SECOND_VERIFIER)['verdict'],
                         'cleared')

    def test_authority_is_answered_before_the_database_is_read(self):
        """A credential that decides nothing costs the store no query.

        The assertion is that the ordinary read path was not entered, which is the observable half of
        "refused before DB access" from inside a test: a refusal that reached for the file first would
        both cost a commit and leak row existence to an unauthorised caller.
        """
        case = self.executed(self.bound('authority-order'))
        case['verification_id'] = self.put(case)['verification_id']
        self.stored(case)
        for actor in (SUMMARY, None, 'reader', Actor('', 'reader'), Actor(123, 'reader'),
                      Actor(['reader'], 'reader'), Actor({'identity': 'reader'}, 'reader'),
                      Actor('bad name', 'reader')):
            with mock.patch.object(state.Store, 'transaction') as read:
                with self.subTest(actor=repr(actor)):
                    self.refused(lambda actor=actor: case['store'].get_verification(
                        case['verification_id'], actor))
                    self.refused(lambda actor=actor: case['store'].get_verification_binding(
                        case['action_id'], actor))
                    self.assertFalse(read.called, 'an unauthorised actor must not reach the database')

    def test_a_read_of_a_stored_statement_is_a_fresh_copy(self):
        """The document is nested four ways deep, so the copy has to be deep in all of them."""
        case = self.executed(self.bound('record-copy'))
        case['verification_id'] = self.put(case)['verification_id']
        pristine = self.stored(case)
        stored = self.stored(case)
        stored['verdict'] = 'cleared'
        stored['samples'].append({'forged': True})
        stored['samples'][0]['value'] = 0.0
        stored['receipt']['sample_count'] = 99999
        stored['origin']['threshold'] = 0.0
        stored['window']['end'] = '2030-01-01T00:00:00+00:00'
        self.assertEqual(self.stored(case), pristine)
        self.assertEqual(self.stored(case)['samples'], pristine['samples'])
        self.assertEqual(self.stored(case)['receipt'], pristine['receipt'])


class AuditBoundaryTests(VerificationFixture):
    """What the write leaves in the audit log: one bounded row on a first write, and nothing otherwise.

    The audit row is the reason this slice is auditable at all, and the two ways to spoil it are to write
    more than the three reviewed fields (which would put verifier payload into the append-only history
    that every other reader has to render) and to route a refused verification write through the
    `action.refused` machinery, whose taxonomy is pinned to the four lifecycle attempts and whose
    classifier maps whole sentences — a new sentence reaching it would land on `unclassified` and quietly
    widen what the refusal budget is for.
    """

    def test_a_first_write_adds_one_bounded_row_and_a_replay_or_conflict_adds_none(self):
        """`verification.recorded` names the id, the verdict and the reason. Not the payload."""
        case = self.executed(self.bound('audit'))
        self.assertEqual(self.ops(case['store'], 'verification.recorded'), [])
        answer = self.put(case)
        case['verification_id'] = answer['verification_id']
        rows = self.ops(case['store'], 'verification.recorded')
        self.assertEqual(len(rows), 1, 'exactly one row for the first accepted write')
        row = rows[0]
        self.assertEqual(row['actor'], VERIFIER.identity)
        self.assertEqual(row['at'], utc_text(RECORD_NOW))
        detail = json.loads(row['detail'])
        self.assertEqual(set(detail), {'verdict', 'reason'})
        self.assertEqual(detail['verdict'], 'cleared')
        self.assertEqual(detail['reason'], 'comparison-satisfied')
        self.assertEqual(row['subject'], answer['verification_id'])
        self.assertLess(len(canonical(detail).encode()), 512, 'a bounded row, not a payload')
        for name in ('samples', 'sample', 'receipt', 'window', 'record', 'payload', 'value', 'sql'):
            self.assertNotIn(name, detail)
        self.refused(lambda: self.put(case, samples=self.rows(case, self.window(case), [150.0])))
        self.put(case, actor=SECOND_VERIFIER)
        self.assertEqual(len(self.ops(case['store'], 'verification.recorded')), 1,
                         'a conflict and a duplicate are not newsworthy')

    def test_refused_verification_writes_are_not_action_refusals(self):
        """Twelve refused attempts, zero `action.refused` rows and zero refusal-audit tokens spent."""
        case = self.executed(self.bound('refusal-boundary'))
        unbound = self.executed(self.bound('refusal-unbound', rule_version='4'))
        running = self.executed(self.bound('refusal-executing'), outcome=None)
        attempts = [
            lambda: self.put(case, actor=UNLISTED),
            lambda: self.put(case, actor=HUMAN),
            lambda: self.put(case, actor=SUMMARY),
            lambda: self.put(case, actor=None),
            lambda: self.put(case, now='yesterday'),
            lambda: self.put(case, window=self.window(case, ends_at=RECORD_NOW + dt.timedelta(hours=1))),
            lambda: self.put(case, binding_id=OTHER_PIN),
            lambda: self.put(unbound),
            lambda: self.put(running),
            lambda: case['store'].get_verification(str(uuid.uuid4()), SUMMARY),
            lambda: case['store'].get_verification_binding('not-a-uuid', READER),
            lambda: case['store'].put_verification(self.statement(case, verdict='cleared'), VERIFIER,
                                                   now=RECORD_NOW)]
        for attempt in attempts:
            self.refused(attempt)
        self.assertEqual(self.ops(case['store'], 'action.refused'), [])
        self.assertEqual(self.ops(case['store'], 'verification.recorded'), [])
        counters = case['store'].refusal_audit_status()
        self.assertEqual([counters[name] for name in ('written', 'dropped', 'failed', 'unauditable')],
                         [0, 0, 0, 0], 'the refusal budget is for the four action attempts, not this')
        answer = self.put(case)
        self.assertEqual(len(self.ops(case['store'], 'verification.recorded')), 1)
        self.assertEqual([row['operation'] for row in case['store'].records('audit', 1)],
                         ['verification.recorded'])
        self.assertIs(answer['created'], True, 'the refusals above must not have wedged anything')


class PolicyOffTests(VerificationFixture):
    """Off is the default, and off must be the platform it was before this slice existed.

    Two spellings of off are checked against each other and against a store that never heard of the
    feature: no extra audit row, no changed action payload, no changed status, and no new write that a
    deployment without a policy file can perform. The last test is the upgrade-and-roll back path — a
    store that held verification data and is reopened without a policy still reads that data to a human
    and still refuses to add to it, which is what makes "verification is off" a safe thing to say on a
    running system.
    """

    def lifecycle(self, name, policy, **event_fields) -> tuple[dict, list]:
        case = self.bound(name, policy=policy, **event_fields)
        self.executed(case)
        operations = [row['operation'] for row in reversed(case['store'].records('audit', 100))]
        return case, operations

    def test_off_is_the_lifecycle_the_platform_already_had(self):
        """Default off, explicit `None`, a matching capture and an unmatching one: same durable facts."""
        default, default_ops = self.lifecycle('off-default', _AUTO)
        for name, policy, event in (('off-none', None, {}),
                                   ('enabled-unmatched', self.policy(), {'rule_version': '4'}),
                                   ('enabled-matched', self.policy(), {})):
            case, operations = self.lifecycle(name, policy, **event)
            with self.subTest(spellings=name):
                self.assertEqual(operations, default_ops,
                                 'capturing a binding adds no audit row and refuses no action')
                self.assertEqual(case['store'].status(), default['store'].status())
        self.assertNotIn('verification.recorded', default_ops)
        self.assertEqual(default['binding'], {'action_id': default['action_id'], 'status': 'unbound',
                                              'reason': 'not-captured', 'binding_id': None,
                                              'origin': None})
        matched = self.lifecycle('enabled-again', self.policy())[0]
        self.assertEqual(matched['binding']['reason'], 'matched', 'the comparison above is not vacuous')

    def test_an_off_store_refuses_writes_and_still_reads_what_an_earlier_enablement_wrote(self):
        """Rolling the policy away must not delete history or open the door it closed.

        A default-off reopen is the rollback an operator actually performs, and the two answers that have
        to be simultaneous are: everything already recorded is still readable and unchanged, and nothing
        new may be recorded — not even by the credential that was writing a moment ago. The old bound
        binding is still `bound` (it is a stored fact, not a live policy lookup) while a newly proposed
        action in the same file is `not-captured`, which is the pair that makes rollback honest.
        """
        case = self.executed(self.bound('rolled-back'))
        answer = self.put(case)
        case['verification_id'] = answer['verification_id']
        written = self.stored(case)
        off = self.open('rolled-back', policy=None)
        self.assertEqual(off.get_verification(case['verification_id'], HUMAN), written)
        self.assertEqual(off.get_verification_binding(case['action_id'], READER), case['binding'])
        self.refused(lambda: off.put_verification(self.statement(
            case, window=self.window(case, ends_at=RECORD_NOW - dt.timedelta(minutes=2))), VERIFIER,
            now=RECORD_NOW))
        self.refused(lambda: off.get_verification(case['verification_id'], VERIFIER))
        second = self.fire(off, minute=1)
        result, _ = self.propose(off, case['incident_id'], [second['event_id']], retry_key='after-rollback')
        self.assertEqual(off.get_verification_binding(result['action_id'], READER)['reason'],
                         'not-captured')
        self.assertEqual(off.get_verification(case['verification_id'], HUMAN), written,
                         'the refused attempts left the stored statement alone')


if __name__ == '__main__':
    unittest.main()

"""detection content compiler tier: every shipped rule is rebuilt here, and every reason for NOT building one is
re-checked against the pinned pySigma backend.

Four things are proven that a green base tier cannot prove, because the base tier only reads committed
artifacts and this file is the only place the compiler actually runs:

* **the committed SQL is the rule's, reproducibly.** Each enabled rule is recompiled and compared to the
  committed JSON as a document, so a rule edited without a rebuild, or an artifact hand-edited beside
  its rule, fails here (`docs/DECISIONS.md` threat detection engine: CI compiles every rule to SQL committed in the
  repo).
* **a rule that is not shipped is not shipped for the reason its file gives.** Each disabled rule either
  fails the gate with the *exact* refusal text it quotes, or — for the one rule that is buildable and
  deliberately unbuilt — compiles cleanly here, which is the only way its own `unshipped.reason` can be
  read as a decision rather than an excuse.
* **the authoring blocks are validated on the build path.** A rule with no `why:`, no `measured:`, an
  unexplained absence, an inline identity list, or an operator parameter whose empty case is permissive
  does not produce an artifact at all. Those are the refusals notification budget and the allowlist port rest on, and
  prose cannot enforce them.
* **a declared operator input cannot reach a shipped artifact.** `parameters:` names an input, it does
  not bind one, and the SQL a parameterized rule builds is byte-identical to the SQL the same rule
  builds with no `parameters:` block at all. `build_gate` therefore refuses to ship one while nothing in
  this build can bind it (#234) while `compile_rule` keeps accepting the declaration — which is the
  difference between authoring validation and shipping enforcement that `CONTRACT.md` now states.

pySigma's own verdict is read too: `errors` must be empty for a rule this repo ships, so the extra
`enabled:`/`why:`/`measured:` blocks are demonstrably inert to the parser and not merely tolerated by
this repository's gate.
"""
import importlib.util
import json
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('sigma_compile', ROOT / 'local_observe/platform/sigma_compile.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

RULES = ROOT / 'examples' / 'sigma'
COMPILED = RULES / 'compiled'


def raw(name: str) -> str:
    return (RULES / (name + '.yaml')).read_text(encoding='utf-8')


def document(name: str) -> dict:
    return yaml.safe_load(raw(name))


def every_rule() -> list[str]:
    return sorted(path.stem for path in RULES.glob('*.yaml'))


def rewritten(text: str, **changes) -> str:
    """Replace or delete (`None`) top-level blocks in rule text that is already in memory."""
    body = yaml.safe_load(text)
    for key, value in changes.items():
        if value is None:
            body.pop(key, None)
        else:
            body[key] = value
    return yaml.safe_dump(body, sort_keys=False, allow_unicode=True)


def edited(name: str, **changes) -> str:
    """One rule's text with top-level blocks replaced or removed (a `None` value deletes the key)."""
    return rewritten(raw(name), **changes)


#: The matcher the board rule cannot use as authored (its own `unshipped.reason` lists why) and that
#: every parameter check below therefore substitutes for it.
WORKING_MATCHER = {'logsource': {'product': 'linux', 'category': 'process_creation'},
                   'detection': {'selection': {'Image|endswith': '/auditctl',
                                               'CommandLine|contains': '-e 0'},
                                 'condition': 'selection'}}


def board_rule(actors: dict | None = None, parameter: str | None = 'actors') -> str:
    """The board rule with its detection replaced by one the pinned mapping accepts.

    The rule as authored cannot compile (that is its stated blocker), so the parameter checks need the
    same file with a matcher that passes the log-source and field gates. The refusals below are then
    about the parameter alone, which is what they are asserting. `actors=None` (or `parameter=None`)
    drops the `parameters:` block entirely, which is the parameter-free control #234 compares against.
    """
    block = None if actors is None or parameter is None else {parameter: actors}
    return edited('board-actor-outside-lane', parameters=block, **WORKING_MATCHER)


class ReproducibleBuildTests(unittest.TestCase):
    """The artifact is the rule, byte for byte, or the pair is broken."""

    def test_each_enabled_rule_rebuilds_to_its_committed_artifact(self) -> None:
        enabled = [name for name in every_rule() if document(name)['enabled'] is True]
        self.assertEqual(['audit-trail-disable', 'process-marker'], enabled)
        for name in enabled:
            with self.subTest(rule=name):
                self.assertEqual(module.compile_rule(raw(name)),
                                 json.loads((COMPILED / (name + '.json')).read_text(encoding='utf-8')))

    def test_the_backend_itself_reports_no_error_against_the_authored_blocks(self) -> None:
        from sigma.collection import SigmaCollection
        for name in [rule for rule in every_rule() if document(rule)['enabled'] is True]:
            collection = SigmaCollection.from_yaml(raw(name))
            self.assertEqual(1, len(collection.rules))
            self.assertEqual([], collection.rules[0].errors,
                             f'{name}: pySigma itself refuses something in this file')

    def test_editing_the_tuning_block_moves_the_rule_version_the_runner_binds_to(self) -> None:
        original = module.compile_rule(raw('audit-trail-disable'))
        retuned = module.compile_rule(edited('audit-trail-disable', measured={
            'false_positives': 0, 'window': '7d', 'population': 'one host', 'measured_on': '2026-09-09',
            'source': 'docs/evidence'}))
        self.assertNotEqual(original['rule_sha256'], retuned['rule_sha256'],
                            'the tuning block is checksummed with the rule, so editing it rotates '
                            'rule_version and an existing cursor refuses rather than drifting')
        self.assertEqual('measured', retuned['measurement']['status'])
        self.assertEqual(0, retuned['measurement']['false_positives'])
        self.assertEqual(original['sql'], retuned['sql'],
                         'metadata must never reach the query: prose is not a predicate')


class NotBuiltForTheStatedReasonTests(unittest.TestCase):
    """A disabled rule is disabled for the reason its file prints."""

    def disabled(self) -> list[str]:
        return [name for name in every_rule() if document(name)['enabled'] is not True]

    def test_a_gate_refusal_still_matches_the_quoted_text(self) -> None:
        checked = 0
        for name in self.disabled():
            block = document(name)['unshipped']
            if 'refusal' not in block:
                continue
            with self.subTest(rule=name):
                with self.assertRaises(ValueError) as caught:
                    module.compile_rule(raw(name))
                self.assertEqual(block['refusal'], str(caught.exception),
                                 'the rule quotes a refusal the pinned gate no longer gives')
                checked += 1
        self.assertEqual(4, checked, 'every compile/construct blocker must quote a refusal here')

    def test_the_policy_blocked_rule_is_buildable_and_deliberately_not_built(self) -> None:
        name = 'privileged-shell-spawn'
        self.assertEqual('policy', document(name)['unshipped']['blocker'])
        artifact = module.compile_rule(raw(name))
        self.assertIn('match_count', artifact['sql'], 'the rule would compile today; it is the window '
                                                     'policy and the missing measurement that hold it')
        with self.assertRaises(ValueError) as refused:
            module.build_gate(raw(name))
        self.assertIn('not enabled', str(refused.exception))
        self.assertIn('maintenance-window policy', str(refused.exception),
                      'the overlay sees the rule\'s own reason, not just a missing file')
        self.assertFalse((COMPILED / (name + '.json')).exists())

    def test_no_artifact_exists_for_any_disabled_rule(self) -> None:
        for name in self.disabled():
            self.assertFalse((COMPILED / (name + '.json')).exists(),
                             f'{name} is disabled and still shipped an artifact')


class AuthoringContractBuildTests(unittest.TestCase):
    """The refusals that make the discipline a build rule. Each is one typed edit of a real rule."""

    def refused(self, text: str) -> str:
        with self.assertRaises(ValueError) as caught:
            module.compile_rule(text)
        return str(caught.exception)

    def test_a_rule_must_state_enabled_and_carry_a_why_and_a_measured_block(self) -> None:
        for change, marker in (({'enabled': None}, 'enabled'),
                               ({'enabled': 'true'}, 'enabled'),
                               ({'why': None}, 'why:'),
                               ({'why': '   '}, 'why:'),
                               ({'measured': None}, 'measured:'),
                               ({'measured': 3}, 'must be a block'),
                               ({'measured': {'false_positives': 0, 'nonsense': 1}}, 'Unknown measured'),
                               ({'measured': {'false_positives': 0}}, 'measured.because'),
                               ({'measured': {'false_positives': None}}, 'measured.because'),
                               ({'measured': {'false_positives': 0, 'window': '7d', 'population': 'h',
                                              'measured_on': 'd', 'source': 's', 'oops': 1}},
                                'Unknown measured')):
            with self.subTest(change=str(change)):
                self.assertIn(marker, self.refused(edited('audit-trail-disable', **change)))

    def test_a_complete_block_is_carried_into_the_artifact_unchanged(self) -> None:
        block = {'false_positives': 4, 'window': '2026-09-01..2026-09-08', 'population': 'one host',
                 'measured_on': '2026-09-09', 'source': 'docs/evidence/2026-09-09-sigma.md'}
        artifact = module.compile_rule(edited('audit-trail-disable', measured=block))
        self.assertEqual({'status': 'measured', 'false_positives': 4, 'window': block['window'],
                          'population': block['population'], 'measured_on': block['measured_on'],
                          'source': block['source']}, artifact['measurement'])

    def test_a_negative_or_non_integer_count_is_refused_rather_than_demoted(self) -> None:
        for count in (-1, 'three', True):
            with self.subTest(count=repr(count)):
                self.assertIn('false_positives', self.refused(
                    edited('audit-trail-disable', measured={'false_positives': count, 'because': 'x'})))
        null = module.compile_rule(edited('audit-trail-disable', measured={
            'false_positives': None, 'because': 'no population has been counted'}))
        self.assertEqual('unmeasured', null['measurement']['status'])
        self.assertEqual('no population has been counted', null['measurement']['reason'])

    def test_an_enabled_rule_cannot_also_claim_to_be_unshipped(self) -> None:
        self.assertIn('pick one', self.refused(
            edited('audit-trail-disable', unshipped={'blocker': 'policy', 'reason': 'y' * 220})))

    def test_a_disabled_rule_must_say_why_and_a_compile_blocker_must_quote_the_refusal(self) -> None:
        text = edited('audit-trail-disable', enabled=False)
        self.assertIn('unshipped: block', self.refused(text))
        self.assertIn('unshipped.blocker', self.refused(edited(
            'audit-trail-disable', enabled=False, unshipped={'blocker': 'vibes', 'reason': 'y' * 220})))
        self.assertIn('unshipped.reason', self.refused(edited(
            'audit-trail-disable', enabled=False, unshipped={'blocker': 'policy'})))
        self.assertIn('must quote the exact refusal', self.refused(edited(
            'audit-trail-disable', enabled=False, unshipped={'blocker': 'compile', 'reason': 'y' * 220})))
        self.assertIn('only for a blocker', self.refused(edited(
            'audit-trail-disable', enabled=False,
            unshipped={'blocker': 'policy', 'reason': 'y' * 220, 'refusal': 'x'})))

    def test_an_identity_list_cannot_be_built_into_an_artifact(self) -> None:
        """The allowlist port, as a refusal: a parameter names an input and never carries it."""
        actors = {'source': 'the operator overlay', 'empty': 'deny-all', 'why_empty_is_safe': 'loud',
                  'lanes': {'act': 'who may write'}, 'values': ['someone', 'someone-else']}
        self.assertIn('no parameter may hold a value', self.refused(self.board(actors)))
        for smuggled in ('logins', 'actors', 'allowlist'):
            with self.subTest(key=smuggled):
                self.assertIn('no parameter may hold a value', self.refused(
                    self.board({'source': 'overlay', 'empty': 'deny-all', 'why_empty_is_safe': 'loud',
                                smuggled: ['someone']})))

    def test_the_empty_case_must_be_the_loud_one(self) -> None:
        """Task 6's fail-closed rule, executable: an absent overlay may never read as "all clear"."""
        base = {'source': 'the operator overlay', 'why_empty_is_safe': 'a missing overlay makes the rule '
                                                                      'report every actor as unknown',
                'lanes': {'act': 'identities expected to write'}}
        for empty in (None, 'allow-all', 'ignore-rule', 'allow-everything', {'a': 'b'}):
            block = dict(base)
            if empty is not None:
                block['empty'] = empty
            with self.subTest(empty=str(empty)):
                self.assertIn('must state empty', self.refused(self.board(block)))
        for empty in ('deny-all', 'refuse-to-build'):
            with self.subTest(safe=empty):
                artifact = module.compile_rule(self.board(dict(base, empty=empty)))
                self.assertEqual(empty, artifact['parameters']['actors']['empty'])

    def board(self, actors: dict) -> str:
        return board_rule(actors)

    def test_a_safe_parameter_survives_into_the_artifact_and_carries_no_value(self) -> None:
        artifact = module.compile_rule(self.board({
            'source': 'the operator overlay', 'empty': 'deny-all', 'lanes': {'act': 'who may write'},
            'why_empty_is_safe': 'every actor reads as unknown until the overlay names one'}))
        self.assertEqual(['actors'], list(artifact['parameters']))
        self.assertEqual({'empty', 'lanes', 'source', 'why_empty_is_safe'},
                         set(artifact['parameters']['actors']))
        self.assertNotIn('someone', json.dumps(artifact), 'an identity did not stay out of the artifact')
        self.assertNotIn('values', artifact['parameters']['actors'])

    def test_a_parameter_without_a_stated_safe_direction_is_refused(self) -> None:
        self.assertIn('why_empty_is_safe', self.refused(self.board(
            {'source': 'overlay', 'empty': 'deny-all', 'lanes': {'act': 'who may write'}})))
        self.assertIn('must name where its value comes from', self.refused(self.board(
            {'empty': 'deny-all', 'why_empty_is_safe': 'loud'})))

    def test_the_compiler_admits_exactly_the_policies_the_documentation_claims(self) -> None:
        """The cross-check behind `tests/test_sigma_rules.py`, which reads these two by AST."""
        self.assertEqual(('deny-all', 'refuse-to-build'), module.PARAMETER_EMPTY)
        self.assertEqual(('compile', 'construct'), module.REFUSAL_BLOCKERS)
        self.assertEqual(('false_positives', 'because', 'window', 'population', 'measured_on', 'source'),
                         module.MEASUREMENT_KEYS)


class ShippingInputGateTests(unittest.TestCase):
    """#234: a *declared* operator input is not a *bound* one, and only the shipping gate can tell.

    `compile_rule` validates a `parameters:` block and carries it into the artifact as metadata, which
    is what lets this tier say anything at all about a rule that must not ship. `build_gate` is the only
    path that writes a committed artifact, and until this card it accepted such a block and emitted SQL
    byte-identical to the same rule with no parameter — so an enabled rule whose mandatory overlay was
    never supplied could be deployed, and a silent window there reads as "all clear". No build-time
    resolver exists and `sigma_runner.tick` binds only its four bounded placeholders, so the gate now
    refuses every declaration instead of trusting an `empty:` line nobody implements.
    """

    #: The card's own reproduction: a mandatory input, an empty lane set, a source naming an overlay
    #: this invocation was never given, and `empty: refuse-to-build`, the loudest spelling available.
    MANDATORY = {'source': 'a deployment overlay this invocation was not given',
                 'why_empty_is_safe': 'a required input must exist before anything is built',
                 'lanes': {}}

    def enabled_with(self, block: dict) -> str:
        """The board rule as an *enabled* rule declaring `block` as its one operator input.

        `enabled: true` (and so no `unshipped:` block) is the point of every case below: the claim is
        about shipping, and `build_gate` refuses a disabled rule on its own `unshipped.reason` before
        it ever reads a `parameters:` block, which would make these assertions true for the wrong
        reason.
        """
        return rewritten(board_rule(block, parameter='required_overlay'), enabled=True, unshipped=None)

    def with_input(self, empty: str) -> str:
        return self.enabled_with(dict(self.MANDATORY, empty=empty))

    def test_a_declared_input_stops_the_build_whichever_way_its_empty_case_is_spelled(self) -> None:
        for empty in module.PARAMETER_EMPTY:
            with self.subTest(empty=empty):
                text = self.with_input(empty)
                self.assertEqual(empty, module.compile_rule(text)['parameters']['required_overlay']['empty'],
                                 'the declaration is valid authoring, and the pure build must keep saying so')
                with self.assertRaises(ValueError) as caught:
                    module.build_gate(text)
                self.assertIn('required_overlay', str(caught.exception),
                              'the refusal has to name the input nobody bound')
                self.assertIn(empty, str(caught.exception),
                              'and carry the policy the author wrote, so the reason is readable')
                self.assertIn('no artifact is built', str(caught.exception))

    def test_a_shipped_rule_that_learns_a_parameter_stops_shipping(self) -> None:
        """The reproduction, on a rule that ships today: the same SQL, and now no artifact.

        The SQL equality is the defect and not an incidental detail: it is why the gate must refuse
        rather than warn, and why relaxing it later needs a query that can actually express the input.
        """
        text = edited('audit-trail-disable', parameters={'required_overlay': dict(self.MANDATORY,
                                                                                 empty='refuse-to-build')})
        committed = json.loads((COMPILED / 'audit-trail-disable.json').read_text(encoding='utf-8'))
        built = module.compile_rule(text)
        self.assertEqual(committed['sql'], built['sql'],
                         'a declared input reached no part of the query: this artifact is the '
                         'parameter-free rule wearing a parameter\'s metadata')
        self.assertEqual(committed['sql_sha256'], built['sql_sha256'])
        self.assertNotEqual(committed['rule_sha256'], built['rule_sha256'],
                            'the two files differ, so only the checksums tell them apart, and the SQL a '
                            'deployment runs is the same statement either way')
        self.assertEqual(['required_overlay'], list(built['parameters']))
        with self.assertRaises(ValueError) as caught:
            module.build_gate(text)
        self.assertIn('required_overlay', str(caught.exception))

    def test_a_declared_input_and_no_input_at_all_build_the_same_query(self) -> None:
        """The parameter-free control, from one file: deleting `parameters:` moves no part of the SQL."""
        with_input = module.compile_rule(self.with_input('deny-all'))
        without = module.compile_rule(board_rule())
        self.assertEqual(without['sql'], with_input['sql'])
        self.assertEqual(without['sql_sha256'], with_input['sql_sha256'])
        self.assertEqual({}, without['parameters'])
        self.assertNotEqual(without['rule_sha256'], with_input['rule_sha256'],
                            'only the rule checksum can tell the two files apart, which is a fact about '
                            'the build, not about what the deployed query can answer')
        with self.assertRaises(ValueError):
            module.build_gate(self.with_input('deny-all'))

    def test_a_malformed_declaration_still_reports_its_own_defect_at_the_gate(self) -> None:
        """The shipping refusal must not arrive early enough to hide a typo in the block."""
        for block, marker in ((dict(self.MANDATORY, empty='allow-all'), 'must state empty'),
                              (dict(self.MANDATORY, values=['someone']), 'no parameter may hold a value'),
                              (dict(self.MANDATORY, source='   '), 'must name where its value comes from'),
                              (self.MANDATORY, 'must state empty')):
            with self.subTest(marker=marker):
                with self.assertRaises(ValueError) as caught:
                    module.build_gate(self.enabled_with(block))
                self.assertIn(marker, str(caught.exception))

    def test_a_parameter_free_rule_pays_nothing_at_the_gate(self) -> None:
        """The positive control: what ships today ships unchanged, artifact document and all."""
        shipped = [name for name in every_rule() if document(name)['enabled'] is True]
        self.assertEqual(['audit-trail-disable', 'process-marker'], shipped)
        for name in shipped:
            with self.subTest(rule=name):
                built = module.build_gate(raw(name))
                self.assertEqual(json.loads((COMPILED / (name + '.json')).read_text(encoding='utf-8')),
                                 built, 'the gate adds a refusal and changes nothing else')
                self.assertEqual(module.compile_rule(raw(name)), built)
                self.assertEqual({}, built['parameters'], 'a shipped artifact names an input nobody binds')

    def test_no_rule_in_the_tree_builds_an_artifact_that_declares_an_input(self) -> None:
        """The same claim as a tree-wide invariant, so a new parameterized rule cannot slip past."""
        for name in every_rule():
            declared = sorted(document(name).get('parameters') or {})
            try:
                built = module.build_gate(raw(name))
            except ValueError:
                continue
            self.assertEqual([], declared, f'{name} built an artifact that declares {declared}')
            self.assertEqual({}, built['parameters'])


class RuleTextBoundTests(unittest.TestCase):
    """The bound the artifact checks is a bound the build must also refuse to produce."""

    def test_a_rule_past_the_build_limit_is_refused_before_parsing(self) -> None:
        text = raw('audit-trail-disable') + '\n# padding to push this rule past the 64 KiB build bound\n' * 1200
        self.assertLess(65536, len(text.encode()))
        with self.assertRaises(ValueError) as caught:
            module.compile_rule(text)
        self.assertIn('build limit', str(caught.exception))

    def test_an_artifact_stays_inside_the_bound_the_runner_refuses_to_execute(self) -> None:
        for name in [rule for rule in every_rule() if document(rule)['enabled'] is True]:
            artifact = module.compile_rule(raw(name))
            with self.subTest(rule=name):
                self.assertLessEqual(len(artifact['sql'].encode()), 65536)
                self.assertLessEqual(len(json.dumps(artifact).encode()), 65536)

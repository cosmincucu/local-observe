"""detection content: the rule-authoring contract, enforced as a build rule over the shipped rule tree.

`tests/test_sigma_content.py` asks whether a compiled rule means what its YAML says. This file asks the
two questions that hold when a rule *cannot* be compiled at all, which is most of this directory:

* **Is every source rule accounted for?** v0.1 shipped six detection rules. Five of them do not survive
  the port, and an unshipped rule with a written reason is a decision while a missing file is a loss.
  The closed list in `V01_RULES` is the completeness check — a seventh source appearing here, or one of
  these six going quiet, fails the job rather than being noticed in review.
* **Is the tuning discipline attached to the rule, or only to the prose about it?** `enabled:`, `why:`,
  `measured:`, `unshipped:` and `parameters:` are checked as *shape*, because a rule whose count lives
  in a commit message has already lost it. The `N rules shipped, M unmeasured` figure an operator reads
  comes from the same blocks, through `sigma_runner.measurement_report`.

Privacy is checked here too, against the same `BANNED_TOKENS` list `scripts/check_foundation.py` gates
on (imported, not copied, so the two cannot disagree), plus the synthetic naming placeholder scheme as an executable
test: an address or domain that is not a placeholder fails the tier, which is what "anonymisation is a
build rule, not a review comment" has to mean to be true.
"""
from __future__ import annotations

import ast
import ipaddress
import re
import sys
import unittest
import uuid
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import check_foundation as foundation_checks  # noqa: E402  (the same BANNED_TOKENS the gate enforces)

from local_observe.platform import sigma_runner  # noqa: E402

SIGMA_COMPILE = ROOT / 'local_observe' / 'platform' / 'sigma_compile.py'

RULES = ROOT / 'examples' / 'sigma'
COMPILED = RULES / 'compiled'
FIXTURES = RULES / 'fixtures'
SCAN_TREES = (RULES, ROOT / 'components' / 'control' / 'sigma')
# The six v0.1 rules this item was asked to harvest, by their file names in the private source tree.
# Nothing here copies their content; this list is what makes "we took the six, five of them do not
# compile, here is each reason" a checkable claim instead of a paragraph in a report.
V01_RULES = ('root-shell-outside-window.yaml', 'windows-audit-log-cleared.yaml', 'auditd-stopped.yaml',
             'dns-blocklist-spike.yaml', 'firewall-block-new-flow.yaml', 'gitea-actor-outside-lane.yaml')
REQUIRED_BLOCKS = ('title', 'id', 'status', 'description', 'author', 'logsource', 'detection', 'level',
                   'enabled', 'measured', 'why')
BLOCKERS = ('compile', 'construct', 'policy', 'noise')
# The synthetic naming placeholder scheme: RFC 8375's `example.test`, RFC 1918 for anything a reader may copy into a
# real file, and loopback for a local endpoint. Anything else is somebody's network.
ALLOWED_NETWORKS = (ipaddress.ip_network('10.11.0.0/16'), ipaddress.ip_network('127.0.0.0/8'))
ALLOWED_DOMAINS = ('example.test', 'example.com', 'example.net', 'example.org', 'example.invalid')
IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAINISH = re.compile(r'\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*'
                       r'\.(?:com|net|org|local|internal|xyz|arpa|io)\b')
BOUNDED_PARAMETERS = ('dataset', 'end_ns', 'resource_id', 'start_ns')


def compiler_constant(name: str) -> Any:
    """Read one module-level constant out of the compiler's own text, without importing it.

    `sigma_compile.py` needs the hash-locked pySigma environment, which exists only in the 3.13 tier, so
    importing it here would turn the base tier into a collection error. Reading the literal is the same
    claim about the same file: if the compiler changes its admitted vocabularies, the assertions below
    move with it or go red, and `tests/compiler/test_sigma_content_rules.py` makes the compiler itself
    agree.
    """
    tree = ast.parse(SIGMA_COMPILE.read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(target, 'id', '') == name for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{SIGMA_COMPILE.name} no longer defines {name}')



def rule_files() -> list[Path]:
    """Every rule in the shipped directory, in name order."""
    return sorted(RULES.glob('*.yaml'))


def rule_document(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding='utf-8'))


class RuleTreeShapeTests(unittest.TestCase):
    """Each rule file is well-formed and carries its blocks, compiled or not."""

    def test_the_directory_is_readable_yaml_and_not_empty(self) -> None:
        self.assertEqual(7, len(rule_files()), 'the shipped rule set is one synthetic fixture plus the '
                                              'six re-derived v0.1 rules')

    def test_every_rule_carries_the_authoring_blocks_and_a_unique_uuid(self) -> None:
        seen: dict[str, str] = {}
        for path in rule_files():
            document = rule_document(path)
            missing = [block for block in REQUIRED_BLOCKS if block not in document]
            self.assertEqual([], missing, f'{path.name} is missing {missing}')
            self.assertIsInstance(document['enabled'], bool, f'{path.name} must say true or false')
            self.assertTrue(str(document['why']).strip(), f'{path.name} has an empty why:')
            self.assertTrue(str(document['description']).strip(), f'{path.name} has an empty description:')
            self.assertEqual('local-observe', document['author'])
            identity = str(document['id'])
            self.assertEqual(identity, str(uuid.UUID(identity)), f'{path.name} id is not a UUID')
            self.assertNotIn(identity, seen, f'{path.name} reuses the id held by {seen.get(identity)}')
            seen[identity] = path.name

    def test_detection_blocks_are_one_condition_over_named_selections(self) -> None:
        for path in rule_files():
            detection = rule_document(path)['detection']
            self.assertIsInstance(detection.get('condition'), str, f'{path.name} needs one condition')
            for name, selection in detection.items():
                if name == 'condition':
                    continue
                self.assertIsInstance(selection, dict, f'{path.name}/{name} must be field selections')
                self.assertTrue(selection, f'{path.name}/{name} is an empty selection, which Sigma'
                                           ' cannot match and this repo cannot mean')

    def test_the_source_rules_are_all_accounted_for(self) -> None:
        quoted = [name for path in rule_files() for name in V01_RULES
                  if name in str(rule_document(path).get('derived_from', ''))]
        for name in V01_RULES:
            self.assertIn(name, quoted, f'{name} is neither shipped here nor named as a source by any '
                                        f'rule in the directory: a rule that simply vanished is a loss, '
                                        f'not a decision')
        self.assertEqual(sorted(V01_RULES), sorted(set(quoted)), 'one v0.1 source must map to exactly '
                                                                 'one re-derived rule file')

    def test_only_the_product_owned_rule_has_no_source(self) -> None:
        derived = [path.name for path in rule_files() if 'derived_from' in rule_document(path)]
        self.assertEqual(6, len(derived), 'the six ports; the synthetic fixture claims no ancestry')
        self.assertNotIn('process-marker.yaml', derived)


class ShippedArtifactPairingTests(unittest.TestCase):
    """`enabled: true` means a committed artifact exists, and nothing else means one does not."""

    def enabled(self) -> list[str]:
        return sorted(path.stem for path in rule_files() if rule_document(path)['enabled'] is True)

    def built(self) -> list[str]:
        return sorted(path.stem for path in COMPILED.glob('*.json'))

    def test_the_enabled_rules_and_the_committed_sql_are_the_same_set(self) -> None:
        self.assertEqual(self.enabled(), self.built(),
                         'a committed SQL file with no enabled rule is a deployment waiting for a rule '
                         'nobody approved, and the reverse is a rule that silently stopped being built')

    def test_a_disabled_rule_states_its_blocker_and_its_reason(self) -> None:
        for path in rule_files():
            document = rule_document(path)
            if document['enabled'] is True:
                self.assertNotIn('unshipped', document)
                continue
            block = document.get('unshipped')
            self.assertIsInstance(block, dict, f'{path.name} is disabled with no unshipped: block')
            self.assertIn(block.get('blocker'), BLOCKERS, f'{path.name} names an unknown blocker')
            self.assertTrue(str(block.get('reason', '')).strip(), f'{path.name} states no reason')
            self.assertGreater(len(str(block['reason'])), 200,
                               f'{path.name} has a reason too short to debug later')
            needs_refusal = block['blocker'] in compiler_constant('REFUSAL_BLOCKERS')
            self.assertEqual(needs_refusal, 'refusal' in block,
                             f'{path.name}: a compile/construct blocker must quote the gate refusal')

    def test_every_shipped_rule_has_its_fixture_pair(self) -> None:
        for name in self.enabled():
            cases = sorted(path.stem for path in (FIXTURES / name).glob('*.json'))
            self.assertIn('positive', cases, f'{name} ships without a positive fixture')
            self.assertIn('negative', cases, f'{name} ships without a negative fixture')
            self.assertIn('absent', cases, f'{name} ships without the absent-sensor case')

    def test_no_fixture_exists_for_a_rule_that_was_not_shipped(self) -> None:
        stray = [path.parent.name for path in FIXTURES.rglob('*.json') if path.parent.name not in self.built()]
        self.assertEqual([], stray, 'a fixture for an unshipped rule promises an executable check that '
                                    'nothing can run')


class PrivateContentTests(unittest.TestCase):
    """synthetic naming as a build rule: this directory may not name anybody's real hosts, addresses or logins."""

    def scanned(self) -> list[Path]:
        return sorted(path for tree in SCAN_TREES for path in tree.rglob('*')
                      if path.is_file() and path.suffix in foundation_checks.SCANNED_SUFFIXES)

    def test_no_estate_identifier_survives_in_the_rule_trees(self) -> None:
        files = self.scanned()
        self.assertTrue(files, 'the rule trees vanished, so this check proves nothing')
        for path in files:
            body = path.read_text(encoding='utf-8')
            for token in foundation_checks.BANNED_TOKENS:
                with self.subTest(path=path.relative_to(ROOT).as_posix(), token=token):
                    self.assertNotIn(token, body)

    def test_every_address_in_the_rule_trees_is_a_placeholder(self) -> None:
        for path in self.scanned():
            for found in IPV4.finditer(path.read_text(encoding='utf-8')):
                address = ipaddress.ip_address(found.group(0))
                with self.subTest(path=path.name, address=found.group(0)):
                    self.assertTrue(any(address in network for network in ALLOWED_NETWORKS),
                                    'synthetic naming puts example addresses in 10.11.0.0/16; anything else is a real '
                                    'host somebody owns')

    def test_every_domain_in_the_rules_is_home_arpa_or_a_reserved_example(self) -> None:
        for path in RULES.glob('*.yaml'):
            for found in DOMAINISH.finditer(path.read_text(encoding='utf-8')):
                with self.subTest(path=path.name, domain=found.group(0)):
                    self.assertTrue(found.group(0).endswith(ALLOWED_DOMAINS),
                                    'synthetic naming reserves example.test for private names; a real domain in a rule is '
                                    'somebody else infrastructure')

    def test_no_selection_value_can_hold_an_identity_or_an_address(self) -> None:
        """Every selection value in the tree, and additionally the compiler's bounds for shipped rules.

        The address/login screens run on every file, including the rules that do not compile: a draft
        that names a real host would leak through the YAML long before the compiler refused it. The
        type and non-emptiness bounds are the compiler's own, and so belong to the rules the compiler
        accepted — the two disabled rules that spell a value as a number or an empty string are doing
        it on purpose, and name that refusal in their `unshipped.reason`.
        """
        for path in rule_files():
            document = rule_document(path)
            for name, selection in document['detection'].items():
                if name == 'condition' or not isinstance(selection, dict):
                    continue
                for key, values in selection.items():
                    for value in (values if isinstance(values, list) else [values]):
                        text = str(value)
                        with self.subTest(rule=path.name, selection=f'{key}={value!r}'):
                            self.assertNotIn('@', text, 'a login or an address does not belong in a matcher')
                            self.assertIsNone(IPV4.search(text), 'matched values carry no addresses')
                            self.assertLessEqual(len(text), 128, 'a matched value is a pattern, not a blob')
                            self.assertNotRegex(text, r'[\x00-\x1f\x7f]', 'control bytes in a matcher')
                            if document['enabled'] is not True:
                                continue
                            self.assertIsInstance(value, str, f'{path.name}: a shipped matcher may not'
                                                              ' match a non-string')
                            self.assertTrue(value, f'{path.name}: a shipped matcher may not hold an empty'
                                                   ' value')
                            self.assertTrue(value.isascii(), 'non-ASCII in a matched value is a rule that'
                                                             ' cannot be typed on another keyboard')

    def test_the_tree_ships_no_allowlist_and_names_one_parameter(self) -> None:
        named = []
        for path in rule_files():
            for name, block in (rule_document(path).get('parameters') or {}).items():
                named.append(f'{path.name}:{name}')
                self.assertNotIn('values', block, f'{path.name}/{name} carries values, which is the file '
                                                  'shape this port refused to copy')
                self.assertEqual('deny-all', block['empty'],
                                 f'{path.name}/{name}: an empty operator input may only make the rule '
                                 f'louder or stop the build')
                self.assertTrue(str(block.get('why_empty_is_safe', '')).strip())
        self.assertEqual(['board-actor-outside-lane.yaml:actors'], named)
        self.assertEqual([], [path.name for path in RULES.rglob('*.txt')],
                         'the source estate kept identities in a .txt beside the rules; nothing here may')


class NoBakedTimeTests(unittest.TestCase):
    """The maintenance-window decision, pinned: no window is ever a literal in a compiled rule."""

    def test_no_compiled_sql_carries_a_date_an_interval_or_a_zone(self) -> None:
        for path in COMPILED.glob('*.json'):
            sql = sigma_runner.artifact(path)['sql']
            with self.subTest(rule=path.stem):
                self.assertIsNone(re.search(r'\d{4}-\d{2}-\d{2}', sql))
                for forbidden in ('INTERVAL', 'toTimeZone', 'now()', 'UTC', 'London'):
                    self.assertNotIn(forbidden, sql)

    def test_the_only_parameters_a_query_may_need_are_the_bounded_four(self) -> None:
        for path in COMPILED.glob('*.json'):
            sql = sigma_runner.artifact(path)['sql']
            with self.subTest(rule=path.stem):
                self.assertEqual(sorted(BOUNDED_PARAMETERS),
                                 sorted(set(re.findall(r'\{(\w+):[A-Za-z0-9]+\}', sql))),
                                 'a fifth placeholder would be an operator input the runner never sends, '
                                 'which is a rule that cannot evaluate and must not pretend to')


class MeasurementHonestyTests(unittest.TestCase):
    """The count an operator reads, and the blocks it is computed from."""

    def test_the_shipped_headline_is_what_the_blocks_say(self) -> None:
        answer = sigma_runner.measurement_report(sorted(COMPILED.glob('*.json')))
        self.assertEqual('2 rules shipped, 2 unmeasured', answer['headline'],
                         'one product fixture and one re-derived rule ship, and neither has a measured '
                         'false-positive rate over a real population')

    def test_a_measured_block_that_names_nothing_cannot_be_the_source_of_the_number(self) -> None:
        for path in rule_files():
            block = rule_document(path).get('measured') or {}
            if block.get('false_positives') is None:
                continue
            self.assertTrue(all(str(block.get(key) or '') for key in ('window', 'population',
                                                                     'measured_on', 'source')),
                            f'{path.name} quotes a count with no window beside it')

    def test_the_build_admits_no_permissive_empty_policy(self) -> None:
        self.assertEqual(('deny-all', 'refuse-to-build'), compiler_constant('PARAMETER_EMPTY'),
                         'a third spelling would have to be argued in, not typed in')

    def test_the_compiler_still_names_the_same_two_blocker_families(self) -> None:
        self.assertEqual(('compile', 'construct'), compiler_constant('REFUSAL_BLOCKERS'),
                         'a blocker that does not quote a refusal is a reason that cannot go stale '
                         'checked, so it must be argued for before it is allowed')

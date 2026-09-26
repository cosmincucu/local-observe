"""The selector grammar and its resolution against a built index (module contract).

Synthetic names throughout (`probe-1`, `demo-api`), with UUIDs derived from those names — the
``tests/test_topology.py`` fixture idiom. The index is built by ``inventory.index.build`` from a real
declaration document, so every assertion here is about the table the product actually serves, not
about a stand-in dictionary.
"""
import datetime as dt
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any

from local_observe.inventory import index, validation
from local_observe.modules import select

NAMESPACE = uuid.NAMESPACE_DNS
REVISION = 'fixture-rev-1'


def identifier(name: str) -> str:
    return str(uuid.uuid5(NAMESPACE, 'modules-fixture/' + name))


def document() -> dict[str, Any]:
    return {'schema_version': 1, 'resources': [
        {'id': identifier('probe-1'), 'kind': 'host', 'name': 'probe-1',
         'aliases': [{'type': 'hostname', 'value': 'probe-1.example.test'},
                     {'type': 'host.id', 'value': 'synthetic-host-001'},
                     {'type': 'ip', 'value': '10.11.0.21'},
                     {'type': 'hostname', 'value': 'probe-1.lan', 'scope': 'lan'}],
         'attributes': {'os': 'linux'}, 'relations': []},
        {'id': identifier('probe-2'), 'kind': 'host', 'name': 'probe-2',
         'aliases': [{'type': 'ip', 'value': 'fe80::1'}],
         'attributes': {'os': 'linux'}, 'relations': []},
        {'id': identifier('demo-api'), 'kind': 'service', 'name': 'demo-api',
         'aliases': [{'type': 'service.name', 'value': 'demo-api', 'scope': 'demo'}],
         'attributes': {'environment': 'demo'},
         'relations': [{'type': 'runs-on', 'target': identifier('probe-1')}]},
    ]}


class SelectorFixture(unittest.TestCase):
    """One built index for the class, in a temporary directory removed on cleanup."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.temp.name) / 'inventory.db'
        cls.metadata = index.build(document(), cls.path, REVISION,
                                   now=dt.datetime(2026, 9, 9, 12, 0, tzinfo=dt.timezone.utc))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def resolve(self, *terms: Any) -> select.Selection:
        return select.resolve(select.parse({'any_of': list(terms)}), self.path)


class GrammarTests(unittest.TestCase):
    def test_a_rule_string_is_refused_and_names_the_grammar_it_replaces(self):
        errors, selector = select.selector_errors('kind=host AND hostname=probe-1.example.test')
        self.assertIsNone(selector)
        sentence = '; '.join(errors)
        self.assertIn('a rule string is not this grammar', sentence)
        self.assertIn('v0.1', sentence)                          # the form the operator copied
        self.assertIn('any_of', sentence)                        # the form to write instead
        self.assertNotIn('probe-1.example.test', sentence)          # the value is not echoed back

    def test_a_prose_string_is_refused_without_the_v01_hint(self):
        errors, _ = select.selector_errors('every linux host')
        self.assertNotIn('v0.1', '; '.join(errors))
        self.assertIn('a rule string is not this grammar', '; '.join(errors))

    def test_any_of_is_the_only_key(self):
        errors, _ = select.selector_errors({'any_of': [{'id': identifier('probe-1')}],
                                            'all_of': []})
        self.assertIn('applies_to.all_of: unknown field', '; '.join(errors))
        errors, _ = select.selector_errors({'kind': 'host'})
        self.assertIn('applies_to.kind: unknown field', '; '.join(errors))
        self.assertIn('applies_to.any_of: missing required field', '; '.join(errors))

    def test_any_of_must_be_a_non_empty_list_inside_a_mapping(self):
        for value in ({}, [], 'x', 4, None, {}):
            with self.subTest(any_of=value):
                errors, selector = select.selector_errors({'any_of': value})
                self.assertIsNone(selector)
                self.assertTrue(errors, value)
        for value in (None, 4, [], 'every linux host'):
            with self.subTest(applies_to=value):
                errors, selector = select.selector_errors(value)
                self.assertIsNone(selector)
                self.assertTrue(errors, value)

    def test_a_term_holds_exactly_one_of_id_and_alias(self):
        cases = ({}, {'kind': 'host'}, {'id': identifier('probe-1'),
                                       'alias': {'type': 'hostname', 'value': 'probe-1.example.test'}},
                 'probe-1', ['id'])
        for item in cases:
            with self.subTest(term=item):
                errors, _ = select.selector_errors({'any_of': [item]})
                self.assertTrue(errors, item)
        errors, _ = select.selector_errors({'any_of': [identifier('probe-1')]})
        self.assertIn('applies_to.any_of[0]: must be a mapping holding exactly one of `id` or `alias`',
                      errors)

    def test_an_id_must_be_a_canonical_lowercase_uuid(self):
        for value in (identifier('probe-1').upper(), 'probe-1', identifier('probe-1')[:-1],
                      identifier('probe-1') + ' ', 7, None):
            with self.subTest(value=value):
                errors, _ = select.selector_errors({'any_of': [{'id': value}]})
                self.assertTrue(errors, value)
        errors, _ = select.selector_errors({'any_of': [{'id': identifier('probe-1') + '/1'}]})
        self.assertIn('applies_to.any_of[0].id', '; '.join(errors))

    def test_an_alias_needs_a_known_type_and_a_bounded_value(self):
        for alias in ({'type': 'mac', 'value': 'aa:bb'}, {'type': 'hostname'},
                      {'value': 'probe-1.example.test'}, {'type': 'hostname', 'value': ''},
                      {'type': 'hostname', 'value': ' '}, {'type': 'hostname', 'value': 'a b'},
                      {'type': 'hostname', 'value': 'x' * 257},
                      {'type': 'hostname', 'value': 'probe-1.example.test', 'zone': 'lan'},
                      {'type': 'hostname', 'value': 'probe-1.example.test', 'scope': 's' * 129},
                      {'type': 'hostname', 'value': 'probe-1.example.test', 'scope': 4},
                      'probe-1.example.test'):
            with self.subTest(alias=alias):
                errors, _ = select.selector_errors({'any_of': [{'alias': alias}]})
                self.assertTrue(errors, alias)

    def test_two_spellings_of_one_target_are_refused_at_parse(self):
        terms = [{'alias': {'type': 'hostname', 'value': 'probe-1.example.test'}},
                 {'alias': {'type': 'hostname', 'value': 'PROBE-1.EXAMPLE.TEST.'}}]
        errors, _ = select.selector_errors({'any_of': terms})
        self.assertIn('names the same target as applies_to.any_of[0]', '; '.join(errors))

    def test_the_term_bound_is_a_refusal_and_not_a_truncation(self):
        terms = [{'id': str(uuid.uuid5(NAMESPACE, f'flood/{step}'))}
                 for step in range(select.MAX_TERMS + 1)]
        errors, selector = select.selector_errors({'any_of': terms})
        self.assertIsNone(selector)
        self.assertIn(f'at most {select.MAX_TERMS} terms', '; '.join(errors))

    def test_parse_raises_what_selector_errors_only_reports(self):
        with self.assertRaises(select.SelectorRefusal) as caught:
            select.parse('kind=host')
        self.assertIn('a rule string', str(caught.exception))
        self.assertIsInstance(caught.exception, validation.InvalidInventory)


class ResolutionTests(SelectorFixture):
    def test_a_declared_uuid_resolves_with_its_kind_and_name(self):
        selection = self.resolve({'id': identifier('probe-1')})
        self.assertEqual(selection.resource_ids, (identifier('probe-1'),))
        self.assertEqual([(match.kind, match.name) for match in selection.matches], [('host', 'probe-1')])

    def test_an_alias_resolves_through_the_indexes_own_normalisation(self):
        for alias in ({'type': 'hostname', 'value': 'probe-1.example.test'},
                      {'type': 'hostname', 'value': 'PROBE-1.Example.Test.'},
                      {'type': 'host.id', 'value': 'synthetic-host-001'},
                      {'type': 'ip', 'value': '10.11.0.21'}):
            with self.subTest(alias=alias):
                self.assertEqual(self.resolve({'alias': alias}).resource_ids,
                                 (identifier('probe-1'),))

    def test_an_ipv6_alias_resolves_from_either_spelling(self):
        self.assertEqual(self.resolve({'alias': {'type': 'ip', 'value': 'FE80::1'}}).resource_ids,
                         (identifier('probe-2'),))

    def test_a_scoped_alias_must_name_its_scope(self):
        self.assertEqual(self.resolve({'alias': {'type': 'hostname', 'value': 'probe-1.lan',
                                                 'scope': 'lan'}}).resource_ids,
                         (identifier('probe-1'),))
        with self.assertRaises(select.SelectorRefusal) as caught:
            self.resolve({'alias': {'type': 'hostname', 'value': 'probe-1.lan'}})
        self.assertIn('applies_to.any_of[0] (alias)', str(caught.exception))
        self.assertIn('name no declared resource', str(caught.exception))

    def test_a_term_that_matches_nothing_is_a_refusal_naming_its_position(self):
        with self.assertRaises(select.SelectorRefusal) as caught:
            self.resolve({'alias': {'type': 'hostname', 'value': 'nowhere.example.test'}})
        sentence = str(caught.exception)
        self.assertIn('applies_to.any_of[0] (alias)', sentence)
        self.assertIn('name no declared resource', sentence)
        self.assertNotIn('nowhere.example.test', sentence)      # the value is not echoed
        with self.assertRaises(select.SelectorRefusal) as caught:
            self.resolve({'id': str(uuid.uuid4())})
        self.assertIn('applies_to.any_of[0] (id)', str(caught.exception))

    def test_every_dead_term_is_named_in_the_one_refusal(self):
        with self.assertRaises(select.SelectorRefusal) as caught:
            self.resolve({'alias': {'type': 'hostname', 'value': 'gone-a.example.test'}},
                         {'id': identifier('probe-1')},
                         {'alias': {'type': 'hostname', 'value': 'gone-b.example.test'}})
        sentence = str(caught.exception)
        self.assertIn('applies_to.any_of[0] (alias)', sentence)
        self.assertIn('applies_to.any_of[2] (alias)', sentence)
        self.assertNotIn('any_of[1]', sentence)

    def test_several_terms_bind_in_term_order(self):
        selection = self.resolve({'id': identifier('demo-api')},
                                 {'alias': {'type': 'host.id', 'value': 'synthetic-host-001'}})
        self.assertEqual(selection.resource_ids, (identifier('demo-api'), identifier('probe-1')))
        self.assertEqual([match.term for match in selection.matches], [0, 1])

    def test_two_terms_reaching_one_resource_by_different_keys_are_refused(self):
        with self.assertRaises(select.SelectorRefusal) as caught:
            self.resolve({'id': identifier('probe-1')},
                         {'alias': {'type': 'host.id', 'value': 'synthetic-host-001'}})
        self.assertIn('two terms resolve to one resource', str(caught.exception))

    def test_the_answer_names_the_declaration_it_came_from(self):
        selection = self.resolve({'id': identifier('probe-1')})
        self.assertEqual(selection.revision['declaration_revision'], REVISION)
        self.assertEqual(selection.revision['declaration_sha256'], self.metadata['declaration_sha256'])
        self.assertTrue(selection.revision['built_at'])

    def test_the_shapes_are_json_safe_and_round_trip(self):
        selector = select.parse({'any_of': [{'id': identifier('probe-1')},
                                            {'alias': {'type': 'host.id',
                                                       'value': 'synthetic-host-002-x'}}]})
        self.assertEqual(select.parse(selector.as_dict()).terms, selector.terms)
        with self.assertRaises(select.SelectorRefusal):
            select.resolve(selector, self.path)         # the second term names nothing
        resolvable = select.parse({'any_of': [{'id': identifier('probe-1')}]})
        selection = select.resolve(resolvable, self.path)
        self.assertEqual([match['kind'] for match in selection.as_dict()['matches']], ['host'])


class UnreadableIndexTests(unittest.TestCase):
    """A broken deployment is never reported as an empty declaration."""

    def refuse_over(self, path: Path) -> str:
        selector = select.parse({'any_of': [{'id': identifier('probe-1')}]})
        with self.assertRaises(select.SelectorRefusal) as caught:
            select.resolve(selector, path)
        return str(caught.exception)

    def test_a_missing_index_is_refused_as_unreadable(self):
        with tempfile.TemporaryDirectory() as temporary:
            sentence = self.refuse_over(Path(temporary) / 'absent.db')
        self.assertIn('could not be read as an index', sentence)
        self.assertNotIn('name no declared resource', sentence)

    def test_a_foreign_file_is_refused_as_unreadable(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'inventory.db'
            path.write_text('this is not a declared inventory index', encoding='utf-8')
            sentence = self.refuse_over(path)
        self.assertIn('could not be read as an index', sentence)

    def test_an_index_with_another_schema_version_is_refused_as_unreadable(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'inventory.db'
            index.build(document(), path, REVISION)
            connection = sqlite3.connect(path)
            connection.execute('PRAGMA user_version=99')
            connection.close()
            sentence = self.refuse_over(path)
        self.assertIn('could not be read as an index', sentence)
        self.assertNotIn('name no declared resource', sentence)

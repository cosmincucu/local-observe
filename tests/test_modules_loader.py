"""The loader's refusal set and its two verdicts — the conformance test of the block format (module contract).

quality bar's "conformance test" artefact for the module contract is *this file*: every promise the schema and
the loader make about refusing bad input is executed here, including the two non-refusals
(``unverified``, ``unchecked``) that keep a module from reading as a pass when nothing was checked.

Fixtures are JSON documents handed to ``ModuleLoader(parser=json.loads)`` — v0.1's idiom, which proves
the schema and the refusal set need no YAML parser — while ``ParseYamlTests`` exercises the real parser
and the visible degradation separately.
"""
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any
from unittest import mock

from local_observe.http import TransportError
from local_observe.inventory import index, validation
from local_observe.modules import loader as module_loader
from local_observe.modules import schema
from local_observe.modules.loader import ModuleCoverage, ModuleLoadError, ModuleLoader, parse_yaml
from local_observe.store import client as store_client
from local_observe.store.backends import memory as memory_backend

ROOT = Path(__file__).resolve().parents[1]
HOST_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, 'modules-fixture/probe-1'))
WINDOW = store_client.Window(start='2026-09-08T10:00:00Z', end='2026-09-08T11:00:00Z')
SAMPLE_STAMP = '2026-09-08T10:30:00Z'


def module_document(**overrides: Any) -> dict[str, Any]:
    """One valid module addressing :data:`HOST_ID`, mutable per keyword argument (``None`` deletes)."""
    document: dict[str, Any] = {
        'schema_version': 1, 'name': 'host-metrics', 'module_version': 1,
        'applies_to': {'any_of': [{'id': HOST_ID}]},
        'collection': {'receiver': 'hostmetrics', 'interval_seconds': 30, 'scrapers': ['cpu'],
                       'resource_attributes': ['host.name', 'resource_id']},
        'datapoints': [{'name': 'system.cpu.time', 'unit': 's', 'type': 'counter'},
                       {'name': 'system.memory.usage', 'unit': 'By', 'type': 'gauge'}],
        'default_graphs': [{'title': 'CPU time', 'datapoints': ['system.cpu.time']}],
        'default_alerts': [{'name': 'cpu-absent', 'datapoint': 'system.cpu.time', 'mode': 'absence',
                            'within_seconds': 300, 'severity': 'warning'}],
    }
    document.update(overrides)
    return {key: value for key, value in document.items() if value is not None}


class DirectoryFixture(unittest.TestCase):
    """A temporary directory of module files, plus an index that declares ``probe-1``."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / 'modules'
        self.directory.mkdir()
        self.index_path = self.root / 'inventory.db'
        index.build({'schema_version': 1, 'resources': [
            {'id': HOST_ID, 'kind': 'host', 'name': 'probe-1',
             'aliases': [{'type': 'hostname', 'value': 'probe-1.example.test'}],
             'attributes': {'os': 'linux'}, 'relations': []}]}, self.index_path, 'fixture-rev-1')

    def write(self, name: str, document: dict[str, Any] | str, *, suffix: str = '.yaml') -> Path:
        text = document if isinstance(document, str) else json.dumps(document)
        path = self.directory / (name + suffix)
        path.write_text(text, encoding='utf-8')
        return path

    def loader(self, **kwargs: Any) -> ModuleLoader:
        kwargs.setdefault('parser', json.loads)
        return ModuleLoader(self.directory, **kwargs)

    def seeded_store(self) -> memory_backend.InMemoryStore:
        return memory_backend.InMemoryStore([store_client.MetricSample(
            name='system.cpu.time', value=1.0, timestamp=SAMPLE_STAMP)])


class LoadingTests(DirectoryFixture):
    def test_valid_files_load_in_sorted_order(self):
        self.write('b-second', module_document(name='b-second'))
        self.write('a-first', module_document(name='a-first'))
        loaded = self.loader().load()
        self.assertEqual([module['name'] for module in loaded], ['a-first', 'b-second'])

    def test_the_returned_documents_are_copies_the_loader_does_not_share(self):
        self.write('only', module_document())
        loader = self.loader()
        original = loader.load()[0]['name']
        loader.load()[0]['name'] = 'mutated'
        loader.modules[0]['name'] = 'mutated'
        loader.load().append({'name': 'injected'})
        self.assertEqual(loader.modules[0]['name'], original)
        self.assertEqual(len(loader.modules), 1)
        # And a render that edits what it was handed cannot change the next render.
        self.assertEqual([module['name'] for module in loader.load()], [original])

    def test_load_twice_replaces_rather_than_appends(self):
        self.write('only', module_document())
        loader = self.loader()
        loader.load()
        loader.load()
        self.assertEqual(len(loader.modules), 1)
        self.assertEqual(len(loader.coverage), 1)

    def test_an_empty_directory_is_a_legitimate_minimal_install(self):
        loaded = self.loader().load()
        self.assertEqual(loaded, [])
        self.assertEqual(self.loader().coverage, ())
        self.assertEqual(self.loader().summary()['modules'], [])

    # -- selection ----------------------------------------------------------

    def test_a_named_index_resolves_the_binding_and_its_provenance(self):
        self.write('only', module_document(
            applies_to={'any_of': [{'alias': {'type': 'hostname', 'value': 'PROBE-1.EXAMPLE.TEST.'}}]}))
        loader = self.loader(index_path=self.index_path)
        loader.load()
        assignments = loader.assignments()
        self.assertEqual([(item.module_name, item.resource_id, item.resource_kind,
                           item.resource_name, item.declaration_revision) for item in assignments],
                         [('host-metrics', HOST_ID, 'host', 'probe-1', 'fixture-rev-1')])
        self.assertEqual(loader.coverage[0].selection, 'resolved')
        self.assertEqual(assignments[0].as_dict()['name'], 'probe-1')

    def test_no_index_named_is_a_stated_gap_and_not_a_pass(self):
        self.write('only', module_document())
        loader = self.loader()
        loader.load()
        self.assertEqual(loader.assignments(), ())
        self.assertEqual(loader.coverage[0].selection, 'unchecked')
        self.assertEqual(loader.coverage[0].resource_ids, ())
        self.assertIn('unchecked', loader.summary()['selection'])

    def test_a_term_that_matches_nothing_refuses_the_module(self):
        self.write('only', module_document(applies_to={'any_of': [{'id': str(uuid.uuid4())}]}))
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader(index_path=self.index_path).load()
        self.assertIn('applies_to', str(caught.exception))
        self.assertIn('name no declared resource', str(caught.exception))
        self.assertEqual(caught.exception.path, str(self.directory / 'only.yaml'))

    # -- series proof -------------------------------------------------------

    def test_a_referenced_series_the_store_shows_is_proven(self):
        self.write('only', module_document())
        loader = self.loader(store=self.seeded_store(), window=WINDOW)
        loader.load()
        coverage = loader.coverage[0]
        self.assertEqual(coverage.series, 'proven')
        self.assertEqual(coverage.proven, ('system.cpu.time',))
        self.assertEqual(coverage.unverified, ())
        # declared, referenced by nothing: intent, and never a proof claim.
        self.assertEqual(coverage.intent, ('system.memory.usage',))
        referenced = set(schema.referenced_datapoints(module_document()))
        self.assertEqual(set(coverage.proven) | set(coverage.unverified), referenced)

    def test_an_absent_series_refuses_the_module_naming_window_and_series(self):
        self.write('only', module_document())
        empty = memory_backend.InMemoryStore()          # the store answers, and the answer is "no rows"
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader(store=empty, window=WINDOW).load()
        sentence = str(caught.exception)
        self.assertIn('system.cpu.time', sentence)
        self.assertIn('fabricated', sentence)
        self.assertIn(WINDOW.start, sentence)
        self.assertIn('default_graphs/default_alerts', sentence)
        self.assertEqual(self.loader(store=empty, window=WINDOW).modules, [])

    def test_the_proof_reads_the_series_name_and_not_just_whether_the_store_has_anything(self):
        """The brief's own case: a graph naming a series the fake store does not have.

        The store is seeded with `system.cpu.time` and the graph is moved to `system.memory.usage`,
        which the module declares and the store has never seen. A check that merely asked "did the store
        answer" would pass this module and ship an empty panel; the refusal must name the series.
        """
        self.write('only', module_document(
            default_graphs=[{'title': 'Memory', 'datapoints': ['system.memory.usage']}]))
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader(store=self.seeded_store(), window=WINDOW).load()
        self.assertIn('system.memory.usage', str(caught.exception))
        self.assertEqual(len(caught.exception.errors), 1)      # the alert's own series stayed proven

    def test_an_unreachable_store_loads_the_module_as_unverified(self):
        class Unreachable:
            def describe(self, query_type, *, window, selectors=None):
                raise TransportError('Store describe unavailable')

        self.write('only', module_document())
        loader = self.loader(index_path=self.index_path, store=Unreachable(), window=WINDOW)
        with self.assertLogs('local_observe.modules.loader', level='WARNING') as logged:
            loaded = loader.load()
        self.assertEqual([module['name'] for module in loaded], ['host-metrics'])
        coverage = loader.coverage[0]
        self.assertEqual(coverage.series, 'unverified')
        self.assertEqual(coverage.unverified, ('system.cpu.time',))       # referenced, and not shown
        self.assertEqual(coverage.proven, ())
        self.assertIn('did not answer', coverage.detail)
        record = logged.records[0]
        self.assertEqual(record.module_name, 'host-metrics')     # what an operator sees, in the log line
        self.assertEqual(record.series, 'unverified')
        self.assertEqual(record.selection, 'resolved')

    def test_a_store_that_refuses_the_question_is_a_module_defect_not_an_outage(self):
        class Refusing:
            def describe(self, query_type, *, window, selectors=None):
                raise store_client.StoreRefused('describe-metrics accepts no selector(s): metric_name')

        self.write('only', module_document())
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader(store=Refusing(), window=WINDOW).load()
        self.assertIn('cannot be asked of the store as a metric name', str(caught.exception))

    def test_a_series_stops_being_asked_once_the_store_stops_answering(self):
        """A store that is down does not need one timeout per declared series to say so."""
        asked: list[str] = []

        class Down:
            def describe(self, query_type, *, window, selectors=None):
                asked.append(selectors['metric_name'])
                raise TransportError('Store describe unavailable')

        self.write('only', module_document(
            default_graphs=[{'title': 'a', 'datapoints': ['system.cpu.time']},
                            {'title': 'b', 'datapoints': ['system.memory.usage']}]))
        loader = self.loader(store=Down(), window=WINDOW)
        loaded = loader.load()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(asked, ['system.cpu.time'])
        coverage = loader.coverage[0]
        self.assertEqual(coverage.series, 'unverified')
        self.assertEqual(set(coverage.unverified), {'system.cpu.time', 'system.memory.usage'})
        self.assertEqual(coverage.proven, ())          # a partly-answered list would read as absences

    def test_a_store_without_a_window_is_refused_before_any_read(self):
        self.write('only', module_document())
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader(store=self.seeded_store()).load()
        self.assertIn('a store with no window is an unanswerable question', str(caught.exception))
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader(window=WINDOW).load()
        self.assertIn('loader:', str(caught.exception))

    def test_unreferenced_datapoints_do_not_have_to_exist_in_the_store_yet(self):
        """The enablement case: a module turns collection on, so its new series cannot already be there."""
        self.write('only', module_document(default_graphs=None, default_alerts=None))
        loader = self.loader(store=memory_backend.InMemoryStore(), window=WINDOW)
        loader.load()
        self.assertEqual(loader.coverage[0].series, 'proven')            # nothing referenced, nothing claimed
        self.assertEqual(loader.coverage[0].intent, ('system.cpu.time', 'system.memory.usage'))


class NoPartialBindTests(DirectoryFixture):
    def test_a_bad_file_leaves_the_loader_holding_nothing(self):
        self.write('a-good', module_document(name='a-good'))
        self.write('b-bad', module_document(name='b-bad', datapoints=[]))
        loader = self.loader(index_path=self.index_path, store=self.seeded_store(), window=WINDOW)
        with self.assertRaises(ModuleLoadError) as caught:
            loader.load()
        self.assertEqual(caught.exception.path, str(self.directory / 'b-bad.yaml'))
        self.assertIn('datapoints: must be a non-empty list', '; '.join(caught.exception.errors))
        self.assertEqual(loader.modules, [])
        self.assertEqual(loader.coverage, ())
        self.assertEqual(loader.assignments(), ())
        self.assertEqual(loader.summary()['modules'], [])

    def test_every_defect_of_one_file_arrives_in_the_one_raise(self):
        self.write('only', module_document(name='Host_CPU', datapoints=[], module_version=0))
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader().load()
        joined = '; '.join(caught.exception.errors)
        for needle in ('name: must be 1-64 characters', 'datapoints: must be a non-empty list',
                       'module_version: must be an integer'):
            self.assertIn(needle, joined)

    def test_a_duplicate_module_name_names_the_file_that_claimed_it(self):
        self.write('a-first', module_document(name='dupe'))
        self.write('b-second', module_document(name='dupe'))
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader().load()
        self.assertIn('duplicate module name', str(caught.exception))
        self.assertIn('a-first.yaml', str(caught.exception))

    def test_a_selector_defect_and_a_schema_defect_are_both_named(self):
        self.write('only', module_document(applies_to='kind=host'))
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader(index_path=self.index_path).load()
        self.assertIn('a rule string is not this grammar', str(caught.exception))


class DirectoryDisciplineTests(DirectoryFixture):
    def test_a_file_the_loader_would_skip_is_a_refusal(self):
        """v0.1 skipped every non-`.yaml` name silently, so a `.yml` module read as enabled and was not."""
        self.write('typo', module_document(), suffix='.yml')
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader().load()
        self.assertIn('typo.yml', str(caught.exception))
        self.assertIn('refuses to skip a file it was given', str(caught.exception))

    def test_documentation_and_dotfiles_are_ignored_by_name(self):
        self.write('only', module_document())
        (self.directory / 'README.md').write_text('# notes', encoding='utf-8')
        (self.directory / 'CONTRACT.md').write_text('# notes', encoding='utf-8')
        (self.directory / '.only.yaml.swp').write_text('junk', encoding='utf-8')
        (self.directory / '.hidden').write_text('junk', encoding='utf-8')
        self.assertEqual([module['name'] for module in self.loader().load()], ['host-metrics'])

    def test_a_subdirectory_is_refused_rather_than_walked_or_ignored(self):
        (self.directory / 'private').mkdir()
        self.write('only', module_document())
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader().load()
        self.assertIn('a subdirectory is not loaded', str(caught.exception))

    def test_a_symlink_is_refused_rather_than_followed(self):
        """Refused on the predicate, not on a created link: the same posture as `anomaly_cursor`."""
        self.write('only', module_document())
        real = self.directory / 'only.yaml'
        with mock.patch.object(Path, 'is_symlink', lambda self: self == real):
            with self.assertRaises(ModuleLoadError) as caught:
                self.loader().load()
        self.assertIn('only.yaml: a symlink is not loaded', str(caught.exception))

    def test_the_loaders_own_state_is_not_a_constructor_argument(self):
        with self.assertRaises(TypeError):
            ModuleLoader(self.directory, parser=json.loads, _coverage=())

    def test_a_missing_directory_is_a_refusal(self):
        loader = ModuleLoader(self.root / 'absent', parser=json.loads)
        with self.assertRaises(ModuleLoadError):
            loader.load()

    def test_an_oversize_file_is_refused_by_name_and_bound(self):
        huge = json.dumps(module_document(description='x' * 70_000))
        (self.directory / 'huge.yaml').write_text(huge, encoding='utf-8')
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader().load()
        self.assertIn('exceeds the', str(caught.exception))
        self.assertIn(f'{module_loader.MAX_MODULE_BYTES}-byte', str(caught.exception))

    def test_a_file_that_is_not_utf8_is_refused(self):
        self.write('only', module_document())
        (self.directory / 'only.yaml').write_bytes(b'\xff\xfe not utf-8')
        with self.assertRaises(ModuleLoadError) as caught:
            self.loader().load()
        self.assertIn('not UTF-8', str(caught.exception))

    def test_a_parser_that_raises_is_reported_as_the_files_defect(self):
        self.write('only', module_document())

        def broken(text: str) -> dict[str, Any]:
            raise ValueError('my parser had a bad day')

        with self.assertRaises(ModuleLoadError) as caught:
            self.loader(parser=broken).load()
        self.assertIn('parse error: ValueError', str(caught.exception))


class ParseYamlTests(unittest.TestCase):
    """The default parser: the inventory's YAML discipline, plus the visible degradation."""

    MODULE_YAML = """
schema_version: 1
name: host-metrics
module_version: 1
applies_to:
  any_of:
    - alias: {type: hostname, value: probe-1.example.test}
collection: {receiver: hostmetrics, interval_seconds: 30}
datapoints:
  - {name: system.cpu.time, unit: s, type: counter}
""".strip()

    def test_the_default_parser_reads_a_module_file(self):
        parsed = parse_yaml(self.MODULE_YAML)
        self.assertEqual(parsed['name'], 'host-metrics')
        self.assertEqual(parsed['applies_to']['any_of'][0]['alias']['value'], 'probe-1.example.test')

    def test_a_duplicate_key_refuses_instead_of_letting_the_later_one_win(self):
        """This is why the inventory's UniqueLoader is reused and not `yaml.safe_load`."""
        with self.assertRaises(ModuleLoadError) as caught:
            parse_yaml(self.MODULE_YAML + '\nname: other-module\n')
        self.assertIn('parse error', str(caught.exception))
        self.assertIn('unique', str(caught.exception).lower())

    def test_an_alias_reference_refuses_because_one_value_read_twice_is_two_values_to_review(self):
        with self.assertRaises(ModuleLoadError) as caught:
            parse_yaml('schema_version: 1\nname: x\nunit: &u s\ndatapoints: '
                       '[{name: a, type: gauge, unit: *u}]\n')
        self.assertIn('aliases are not supported', str(caught.exception))

    def test_text_that_is_not_a_mapping_is_refused(self):
        for text in ('- one\n- two\n', 'a string\n', '\n'):
            with self.subTest(text=text.strip()[:12]):
                with self.assertRaises(ModuleLoadError) as caught:
                    parse_yaml(text)
                self.assertIn('mapping', str(caught.exception))

    def test_a_missing_pyyaml_degrades_visibly_naming_the_dependency(self):
        """v0.1's discipline, provable here by hiding the module rather than by uninstalling it."""
        with mock.patch.dict(sys.modules, {'yaml': None}):
            with self.assertRaises(ModuleLoadError) as caught:
                parse_yaml('schema_version: 1\n')
        sentence = str(caught.exception)
        self.assertIn('module loading requires pyyaml', sentence)
        self.assertIn('base dependency', sentence)
        self.assertNotIn("modules' extra", sentence)     # there is no such extra, and none is promised

    def test_the_loader_reports_the_parser_failure_against_the_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'broken.yaml'
            path.write_text('schema_version: 1\nname: [unclosed\n', encoding='utf-8')
            with self.assertRaises(ModuleLoadError) as caught:
                ModuleLoader(temporary).load()
        self.assertIn('broken.yaml', str(caught.exception))


class VerdictRecordTests(unittest.TestCase):
    def test_the_two_verdict_fields_answer_two_questions(self):
        record = ModuleCoverage(module='m', selection='resolved', series='proven', resource_ids=(),
                                proven=('a',), intent=(), unverified=(), detail='answered')
        self.assertEqual(record.as_dict()['series'], 'proven')
        self.assertEqual(record.as_dict()['selection'], 'resolved')

    def test_a_verdict_word_this_package_never_emits_is_refused(self):
        """`absent` is an answered absence, and an answered absence is a raise, never a state."""
        base = dict(module='m', resource_ids=(), proven=(), intent=(), unverified=(), detail='')
        with self.assertRaises(ValueError):
            ModuleCoverage(selection='resolved', series='absent', **base)
        with self.assertRaises(ValueError):
            ModuleCoverage(selection='matched', series='proven', **base)


class ShippedExampleTests(unittest.TestCase):
    """examples/modules/ is held to the contract by this suite, on the shipped inventory example."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.index_path = Path(self.temp.name) / 'inventory.db'
        index.build(validation.read_document(ROOT / 'examples/inventory/declared.yaml'),
                    self.index_path, 'examples-rev-1')

    def test_the_reference_module_binds_the_reference_declaration(self):
        loader = ModuleLoader(ROOT / 'examples/modules', index_path=self.index_path)
        loaded = loader.load()
        self.assertEqual([module['name'] for module in loaded], ['host-metrics'])
        assignments = loader.assignments()
        self.assertEqual([(item.resource_id, item.resource_kind) for item in assignments],
                         [('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', 'host')])
        self.assertEqual(loader.coverage[0].selection, 'resolved')

    def test_the_reference_module_proves_itself_against_a_store_that_has_its_series(self):
        seeded = memory_backend.InMemoryStore([store_client.MetricSample(
            name='system.cpu.time', value=2.0, timestamp=SAMPLE_STAMP)])
        loader = ModuleLoader(ROOT / 'examples/modules', index_path=self.index_path,
                              store=seeded, window=WINDOW)
        loader.load()
        self.assertEqual(loader.coverage[0].series, 'proven')
        self.assertEqual(loader.coverage[0].proven, ('system.cpu.time',))

    def test_the_only_datapoint_it_declares_is_the_one_this_repo_names(self):
        loader = ModuleLoader(ROOT / 'examples/modules')
        module = loader.load()[0]
        self.assertEqual([point['name'] for point in module['datapoints']], ['system.cpu.time'])
        collector = (ROOT / 'components/data/agent-linux/collector.yaml').read_text()
        self.assertIn('system.cpu.time', collector)                      # the name is quoted, not invented
        for scraper in module['collection']['scrapers']:
            self.assertIn(f'{scraper}:', collector)
        self.assertEqual(module['collection']['interval_seconds'], 30)   # collection_interval: 30s
        for attribute in module['collection']['resource_attributes']:
            self.assertIn(attribute, collector)


class OptionalDependencyTests(unittest.TestCase):
    """A declaration parser that needs an optional service is a declaration parser that is broken."""

    def test_the_package_imports_without_any_optional_extra(self):
        program = '''
import importlib.abc
import sys
class NoExtras(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'mcp', 'uvicorn', 'datasette', 'datasette_graphql'}:
            raise ModuleNotFoundError('Optional dependency blocked by test: ' + fullname)
sys.meta_path.insert(0, NoExtras())
from local_observe.modules import schema, select, loader, compiler
result = schema.validate({'schema_version': 1})
assert not result.ok and any('missing required field' in error for error in result.errors), result
'''
        completed = subprocess.run([sys.executable, '-B', '-c', program], cwd=ROOT,
                                   capture_output=True, text=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == '__main__':
    unittest.main()

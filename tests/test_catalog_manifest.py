"""The entry manifest's refusal set: a catalogue entry cannot claim what it has not done (module catalog).

quality bar's conformance artefact for the catalogue is *this file plus* ``test_catalog_registry.py``: every
promise :mod:`local_observe.catalog.manifest` makes about refusing bad input is executed here. Fixtures
are dicts — the schema check is pure and touches no filesystem, which is the split the module documents.

The two refusals that decide whether a catalogue is information or marketing are ``validated`` without an
evidence path and an inline pin; both are asserted from more than one direction here, and the shipped
seeds are walked in ``test_catalog_registry.py`` so a seed cannot quietly grow a version number later.

``ReferenceConfinementTests`` is the other half of what makes a reference mean something: every path a
manifest may name is checked **as a whole string** before :mod:`.registry` joins it to a checkout, so
``..``, an absolute form, a drive, a backslash separator, an empty or dot-only segment and a control
terminator are refused here, without a filesystem being asked anything. The registry's own tests carry the
resolved-path half (a symlinked parent) and the tripwire that proves no outside file is opened.
"""
import copy
import json
import re
import unittest
from pathlib import Path
from typing import Any

from local_observe.catalog import manifest
from local_observe.catalog.manifest import validate

ROOT = Path(__file__).resolve().parents[1]


def entry_document(**overrides: Any) -> dict[str, Any]:
    """One valid manifest, with any key replaced by a keyword argument (``None`` deletes it)."""
    document: dict[str, Any] = {
        'schema_version': 1,
        'name': 'example-integration',
        'entry_version': 1,
        'description': 'An optional console an operator runs beside the stack and links from the portal.',
        'decided_by': 'D-101',
        'capabilities': ['container-execution', 'operator-access'],
        'components': [{'path': 'components/control/homepage', 'state': 'selected',
                        'relationship': 'surface'}],
        'modules': [],
        'if_disabled': 'The portal shows no link; collection and detection are untouched.',
    }
    document.update(overrides)
    return {key: value for key, value in document.items() if value is not None}


def errors_of(manifest_document: dict[str, Any]) -> list[str]:
    """The refusal sentences one document earns (empty means it was accepted)."""
    return list(validate(manifest_document).errors)


def any_error_matching(errors: list[str], *needles: str) -> bool:
    return any(all(needle in error for needle in needles) for error in errors)


class AcceptedTests(unittest.TestCase):
    """The positive controls: what a real entry looks like, and what the validator says about it."""

    def test_a_reference_manifest_is_accepted(self) -> None:
        self.assertEqual([], errors_of(entry_document()))

    def test_validate_returns_a_result_and_never_raises_on_garbage(self) -> None:
        """A manifest an author hand-wrote can be anything; the answer is still one result per call."""
        for value in (None, [], 7, 'text', {'name': 3}, [{}], True, {'components': [None, 5]},
                      {'modules': 'host-metrics'}, {'capabilities': 'container-execution'}):
            with self.subTest(value=value):
                result = validate(value)
                self.assertFalse(result.ok)
                self.assertTrue(result.errors, 'a refusal with no reason named is not a refusal')

    def test_an_entry_may_name_a_module_and_no_component(self) -> None:
        errors = errors_of(entry_document(components=[], modules=[{'name': 'host-metrics',
                                                                  'min_module_version': 1}]))
        self.assertEqual([], errors)

    def test_the_manifest_is_json_data_and_a_json_round_trip_changes_nothing(self) -> None:
        document = entry_document()
        self.assertEqual([], errors_of(json.loads(json.dumps(document))))
        self.assertEqual([], errors_of(copy.deepcopy(document)))


class FieldDisciplineTests(unittest.TestCase):
    """Closed key set, the version seam, and the shapes that keep a name usable as a directory name."""

    def test_an_unknown_field_is_refused_naming_it(self) -> None:
        errors = errors_of(entry_document(extra_field='whatever'))
        self.assertTrue(any_error_matching(errors, 'extra_field', 'unknown field'))

    def test_every_required_field_is_named_when_missing(self) -> None:
        for key in manifest.ENTRY_REQUIRED:
            with self.subTest(key=key):
                errors = errors_of(entry_document(**{key: None}))
                self.assertTrue(any_error_matching(errors, key, 'missing required field'), errors)

    def test_a_schema_version_this_file_does_not_know_is_refused_not_reinterpreted(self) -> None:
        for version in (2, '1', 0, None):
            with self.subTest(version=version):
                errors = errors_of(entry_document(schema_version=version))
                self.assertTrue(any_error_matching(errors, 'schema_version'), errors)

    def test_an_entry_name_is_r_p12s_module_name_shape(self) -> None:
        """The same compiled pattern, so the two vocabularies cannot drift apart."""
        self.assertIs(manifest.NAME_SHAPE, manifest.module_schema.NAME_SHAPE)
        for name in ('Portainer', 'with space', 'with/slash', '1lead', '.hidden', 'a' * 65, ''):
            with self.subTest(name=name):
                self.assertTrue(any_error_matching(errors_of(entry_document(name=name)), 'name'), name)

    def test_entry_version_is_an_integer_the_package_never_orders_by(self) -> None:
        for value in (0, -1, '1', 1.0, True, None):
            with self.subTest(value=value):
                self.assertTrue(any_error_matching(errors_of(entry_document(entry_version=value)),
                                                   'entry_version'), value)

    def test_an_entry_that_names_no_decision_is_refused(self) -> None:
        """Q/D ids are the two registers this repository lets authorise an integration."""
        for value in ('FEATURE-42', 'Q-', 'q-11', '', 'deployment separation follow-up'):
            with self.subTest(value=value):
                self.assertTrue(any_error_matching(errors_of(entry_document(decided_by=value)),
                                                   'decided_by'), value)
        for value in ('D-101', 'D-102a', 'Q-101'):
            with self.subTest(value=value):
                self.assertEqual([], errors_of(entry_document(decided_by=value)))


class CapabilityTests(unittest.TestCase):
    """Capabilities are the only thing an entry may require of a deployment (component independence)."""

    def test_an_unknown_capability_is_refused_naming_the_vocabulary(self) -> None:
        errors = errors_of(entry_document(capabilities=['worker-host-has-docker']))
        self.assertTrue(any_error_matching(errors, 'capabilities[0]', 'not a declared capability'),
                        errors)
        self.assertIn('container-execution', errors[0], 'the refusal must list what is admissible')

    def test_a_capability_list_is_non_empty_bounded_and_unique(self) -> None:
        cases = {'empty': [], 'not a list': 'probes', 'too many': list(manifest.CAPABILITIES) +
                 list(manifest.CAPABILITIES), 'duplicate': ['probes', 'probes'],
                 'nested': [{'name': 'probes'}]}
        for label, value in cases.items():
            with self.subTest(case=label):
                self.assertTrue(any_error_matching(errors_of(entry_document(capabilities=value)),
                                                   'capabilities'), value)

    def test_a_capability_never_carries_a_host_name_a_path_or_a_credential(self) -> None:
        """There is no field for one; this asserts the shape of the vocabulary, not an author's intent."""
        for capability in manifest.CAPABILITIES:
            with self.subTest(capability=capability):
                self.assertRegex(capability, r'^[a-z][a-z0-9-]*$')
                self.assertNotIn('/', capability)
                self.assertNotIn('.', capability)


class ComponentReferenceTests(unittest.TestCase):
    """A component reference: the path shape, the state vocabulary, the relationship, the pin pointer."""

    def test_a_path_must_be_a_component_directory_name_and_nothing_else(self) -> None:
        for path in ('components/data', 'components/data/store-signoz/compose.yaml',
                     '../components/data/store-signoz', '/etc/passwd', 'examples/full',
                     'components/data/store-signoz/', 'local_observe/platform'):
            with self.subTest(path=path):
                document = entry_document(components=[{'path': path, 'state': 'selected',
                                                       'relationship': 'surface'}])
                self.assertTrue(any_error_matching(errors_of(document), 'components[0].path'), path)

    def test_a_state_outside_the_three_words_is_refused(self) -> None:
        for state in ('production-ready', 'built', 'partial', 'GA', None):
            with self.subTest(state=state):
                document = entry_document(components=[{'path': 'components/control/homepage',
                                                       'state': state, 'relationship': 'surface'}])
                self.assertTrue(any_error_matching(errors_of(document), 'components[0].state'), state)

    def test_the_relationship_vocabulary_is_closed(self) -> None:
        """``related-to`` is refused because a reader would take it for ``installed by this entry``."""
        for relationship in ('related-to', 'depends-on', 'installs', 'bundled'):
            with self.subTest(relationship=relationship):
                document = entry_document(components=[{'path': 'components/control/homepage',
                                                       'state': 'selected',
                                                       'relationship': relationship}])
                self.assertTrue(any_error_matching(errors_of(document), 'components[0].relationship'),
                                relationship)

    def test_a_relationship_that_names_a_build_must_point_at_its_pin(self) -> None:
        for relationship in manifest.PIN_BEARING:
            with self.subTest(relationship=relationship):
                document = entry_document(components=[{'path': 'components/control/platform',
                                                       'state': 'selected',
                                                       'relationship': relationship}])
                self.assertTrue(any_error_matching(errors_of(document), 'components[0].pin',
                                                   'missing required field'), relationship)

    def test_a_pin_is_two_fields_and_no_third(self) -> None:
        cases: dict[str, Any] = {
            'a third field': {'file': 'components/control/platform/versions.json', 'key': 'gatus_image',
                              'value': 'whatever'},
            'not a mapping': 'twinproduction/gatus',
            'no key': {'file': 'components/control/platform/versions.json'},
            'no file': {'key': 'gatus_image'},
        }
        for label, pin in cases.items():
            with self.subTest(case=label):
                document = entry_document(components=[{'path': 'components/control/platform',
                                                       'state': 'selected',
                                                       'relationship': 'pin-holder', 'pin': pin}])
                self.assertTrue(any_error_matching(errors_of(document), 'components[0].pin'), label)

    def test_a_pin_file_is_one_of_the_two_files_that_own_a_pin(self) -> None:
        for file_value in ('versions.json', 'components/versions.json',
                           'components/control/platform/upgrade.md',
                           'docs/evidence/note.md', 'examples/full/.env.example'):
            with self.subTest(file=file_value):
                document = entry_document(components=[{'path': 'components/control/platform',
                                                       'state': 'selected',
                                                       'relationship': 'pin-holder',
                                                       'pin': {'file': file_value,
                                                               'key': 'gatus_image'}}])
                self.assertTrue(any_error_matching(errors_of(document), 'components[0].pin.file'),
                                file_value)

    def test_a_pin_key_is_a_dotted_object_path_with_no_list_position(self) -> None:
        for key_value in ('images.0.image', 'gatus image', '', '.gatus_image', 'a.b.c.d.e.f.g'):
            with self.subTest(key=key_value):
                document = entry_document(components=[{'path': 'components/control/platform',
                                                       'state': 'selected',
                                                       'relationship': 'pin-holder',
                                                       'pin': {'file': 'components/a/b/versions.json',
                                                               'key': key_value}}])
                self.assertTrue(any_error_matching(errors_of(document), 'components[0].pin.key'),
                                key_value)

    def test_a_duplicate_component_reference_is_refused(self) -> None:
        one = {'path': 'components/control/homepage', 'state': 'selected', 'relationship': 'surface'}
        self.assertTrue(any_error_matching(errors_of(entry_document(components=[one, dict(one)])),
                                           'duplicate component reference'))


class EvidenceAndStateTests(unittest.TestCase):
    """The refusal that keeps the word ``validated`` meaning what quality bar says it means."""

    def test_validated_without_an_evidence_path_is_refused(self) -> None:
        document = entry_document(components=[{'path': 'components/control/homepage',
                                               'state': 'validated', 'relationship': 'surface'}])
        errors = errors_of(document)
        self.assertTrue(any_error_matching(errors, 'components[0].conformance_evidence'), errors)
        self.assertTrue(any_error_matching(errors, 'quality bar'), errors)

    def test_an_evidence_path_is_a_file_in_this_checkout_and_stays_inside_it(self) -> None:
        for evidence in ('../../etc/passwd', 'etc/passwd', '/etc/passwd', 'components',
                         'STATUS.md', 'components//control'):
            with self.subTest(evidence=evidence):
                document = entry_document(components=[{'path': 'components/control/homepage',
                                                      'state': 'validated', 'relationship': 'surface',
                                                      'conformance_evidence': evidence}])
                self.assertTrue(any_error_matching(errors_of(document), 'conformance_evidence'),
                                evidence)

    def test_an_evidence_path_under_a_shipped_tree_is_accepted(self) -> None:
        document = entry_document(components=[{'path': 'components/control/homepage',
                                               'state': 'validated', 'relationship': 'surface',
                                               'conformance_evidence':
                                                   'docs/evidence/example-note.md'}])
        self.assertEqual([], errors_of(document))


class ReferenceConfinementTests(unittest.TestCase):
    """Every whole-reference shape that could name a file outside the checkout, refused by the document.

    The manifest is the layer that must not let a path that *climbs* reach
    :mod:`.registry`, which is the layer that asks a filesystem questions — and the asking is the leak,
    because a pin key that does not resolve quotes the keys of the file it opened. Two of these forms
    were the real bypass: a character class that admits ``.`` admits ``..``, and ``$`` matches before a
    trailing newline. The rest are the neighbours of that bug, listed because each is a way a Windows,
    UNC or URL parser finds a different file than the one the reader anchored.
    """

    #: (a whole reference, the phrase its refusal must contain). Every one of these was accepted as a
    #  path by the shipped grammar before this check existed, or is one edit away from being one.
    OUT_OF_TREE_REFERENCES: tuple[tuple[str, str], ...] = (
        ('components/../../outside/components/engine/versions.json', 'climb out of it'),
        ('docs/../../outside/docs/evidence/canary.md', 'climb out of it'),
        ('components/control/../../outside/components/engine/versions.json', 'climb out of it'),
        ('docs/evidence/../../../etc/passwd', 'climb out of it'),
        ('components/.../engine/versions.json', 'nothing but dots'),
        ('components/./engine/versions.json', 'climb out of it'),
        ('components/control/platform/versions.json\n', 'control character'),
        ('docs/evidence/note.md\n', 'control character'),
        ('docs/evidence/note.md\r.md', 'control character'),
        ('docs/evidence/note.md\x00', 'control character'),
        ('components\\control\\platform\\versions.json', 'backslash'),
        ('\\\\server\\share\\versions.json', 'backslash'),
        ('/etc/versions.json', 'absolute'),
        ('C:/windows/versions.json', 'drive letter'),
        ('//server/share/versions.json', 'UNC'),
        ('components//engine/versions.json', 'empty segment'),
        ('components/engine/versions.json/', 'empty segment'),
        ('components/engine/versions.json.', 'ending in a dot'),
        ('docs/evidence/note.md.', 'ending in a dot'),
        (' docs/evidence/note.md', 'whitespace'),
        ('docs/evidence/note.md ', 'whitespace'),
    )

    #: The grammar this card must not narrow: every form a shipped or plausible entry may write.
    SHIPPED_FORMS = ('components/control/platform/versions.json',
                     'components/data/store-signoz/image-lock.json',
                     'components/a/b/c/versions.json', 'components/control/home.page',
                     'docs/evidence/example-note.md', 'docs/evidence/.draft-note.md',
                     'local_observe/catalog/README.md', 'examples/catalog/README.md')

    def document_with(self, field: str, value: str) -> dict[str, Any]:
        """A one-component document whose only path is *value*, as a pin file or as an evidence path."""
        if field == 'pin':
            component: dict[str, Any] = {'path': 'components/control/platform', 'state': 'selected',
                                         'relationship': 'pin-holder',
                                         'pin': {'file': value, 'key': 'gatus_image'}}
        else:
            component = {'path': 'components/control/homepage', 'state': 'validated',
                         'relationship': 'surface', 'conformance_evidence': value}
        return entry_document(components=[component])

    def test_the_helper_names_why_each_form_is_not_a_relative_path(self) -> None:
        for value, phrase in self.OUT_OF_TREE_REFERENCES:
            with self.subTest(value=repr(value)):
                problem = manifest.lexical_reference(value)
                self.assertIsNotNone(problem, f'{value!r} read as a path inside the checkout')
                self.assertIn(phrase, problem or '')

    def test_the_helper_refuses_what_is_not_a_path_at_all(self) -> None:
        for value in ('', ' ', None, 7, [], {}, True, b'docs/evidence/note.md'):
            with self.subTest(value=repr(value)):
                self.assertIsNotNone(manifest.lexical_reference(value))

    def test_an_out_of_tree_reference_is_refused_in_either_field_that_names_one(self) -> None:
        """Both path fields are confined: the pin pointer and the evidence path of a ``validated`` claim."""
        for value, phrase in self.OUT_OF_TREE_REFERENCES:
            for field in ('pin', 'evidence'):
                with self.subTest(value=repr(value), field=field):
                    errors = errors_of(self.document_with(field, value))
                    needle = ('components[0].pin.file' if field == 'pin'
                              else 'components[0].conformance_evidence')
                    self.assertTrue(any_error_matching(errors, needle, phrase),
                                    f'{needle} + {phrase!r} absent from {errors}')

    def test_the_shipped_relative_grammar_still_parses(self) -> None:
        """The positive control: nothing a real entry may write became harder to write.

        A name may start with a dot, contain dots, contain a hyphen or an underscore, and sit as deep as
        it likes — the alphabet is the shapes' and is unchanged. Only climbing left the grammar.
        """
        for value in self.SHIPPED_FORMS:
            with self.subTest(value=value):
                self.assertIsNone(manifest.lexical_reference(value))
        for value in ('components/control/platform/versions.json',
                      'components/data/store-signoz/image-lock.json'):
            with self.subTest(pin=value):
                self.assertEqual([], errors_of(self.document_with('pin', value)))
        for value in ('docs/evidence/example-note.md', 'local_observe/catalog/README.md',
                      'examples/catalog/README.md'):
            with self.subTest(evidence=value):
                self.assertEqual([], errors_of(self.document_with('evidence', value)))

    def test_a_pin_key_is_matched_as_a_whole_string_too(self) -> None:
        """The key is not a path, and the same ``$`` habit reached it: a trailing newline is no key."""
        for key_value in ('gatus_image\n', 'gatus\r_image'):
            with self.subTest(key=repr(key_value)):
                document = self.document_with('pin', 'components/control/platform/versions.json')
                document['components'][0]['pin']['key'] = key_value
                self.assertTrue(any_error_matching(errors_of(document), 'components[0].pin.key'),
                                repr(key_value))


class ModuleReferenceTests(unittest.TestCase):
    """Modules are referenced by module contract id and revision, never copied into the entry."""

    def test_an_inline_module_mapping_is_refused(self) -> None:
        """v0.1 allowed a whole module mapping inline; here that is a second copy of a module."""
        embedded = {'schema_version': 1, 'name': 'host-metrics', 'module_version': 1}
        for value in ([embedded], ['host-metrics.yaml'], [4], [{'name': 'Bad Name'}],
                      [{'name': 'host-metrics', 'min_module_version': 0}],
                      [{'name': 'host-metrics', 'datapoints': []}]):
            with self.subTest(value=value):
                self.assertTrue(any_error_matching(errors_of(entry_document(modules=value)),
                                                   'modules'), value)

    def test_a_duplicate_module_reference_is_refused(self) -> None:
        reference = {'name': 'host-metrics'}
        self.assertTrue(any_error_matching(errors_of(entry_document(modules=[reference,
                                                                            dict(reference)])),
                                           'duplicate module reference'))

    def test_the_module_id_shape_is_the_module_contracts_own(self) -> None:
        document = entry_document(modules=[{'name': 'system.cpu.time'}])
        self.assertEqual([], errors_of(document), 'a module name may contain dots')


class SentenceTests(unittest.TestCase):
    """``if_disabled`` answers component independence's second half in one sentence or does not answer it."""

    def test_a_multi_sentence_or_multi_line_answer_is_refused(self) -> None:
        for value in ('Collection keeps working. Detection keeps working.',
                      'Collection keeps working\nDetection keeps working.',
                      'collection keeps working', '   ', '',
                      'x' * 321):
            with self.subTest(value=value):
                self.assertTrue(any_error_matching(errors_of(entry_document(if_disabled=value)),
                                                   'if_disabled'), value)

    def test_one_line_and_one_terminator_are_enough(self) -> None:
        for value in ('Nothing else changes.', 'Nothing else changes!'):
            with self.subTest(value=value):
                self.assertEqual([], errors_of(entry_document(if_disabled=value)))


class InlinePinRefusalTests(unittest.TestCase):
    """A pin is a pointer into the file that owns it; four shapes of copy are refused by field path."""

    def document_with(self, text: str) -> dict[str, Any]:
        return entry_document(description=text)

    def test_a_digest_anywhere_is_refused_naming_the_field(self) -> None:
        for text in ('pinned to sha256:2b9a3f5c1d8e7a6b5c4d3e2f10987654321abcdef',
                     'the digest is 2b9a3f5c1d8e7a6b5c4d3e2f10987654321abcdef01234'):
            with self.subTest(text=text):
                errors = errors_of(self.document_with(text))
                self.assertTrue(any_error_matching(errors, 'description', 'content digest'), text)
                self.assertNotIn(text, ' '.join(errors), 'the refusal must not echo the pin back')

    def test_a_dotted_version_in_prose_is_refused(self) -> None:
        """A version *sentence* is the drift this rule exists to stop, so prose is scanned too."""
        for text in ('pinned to 1.2.3 of the console', 'runs on python 3.12', 'see v0.4.0 upstream'):
            with self.subTest(text=text):
                self.assertTrue(any_error_matching(errors_of(self.document_with(text)),
                                                   'dotted version number'), text)

    def test_an_image_reference_or_a_registry_host_is_refused(self) -> None:
        for text in ('the image is twinproduction/gatus:some-tag', 'pulled from ghcr.io today',
                     'mirror at registry.example.com'):
            with self.subTest(text=text):
                errors = errors_of(self.document_with(text))
                self.assertTrue(any_error_matching(errors, 'description'), errors)

    def test_an_inline_pin_in_a_component_reference_is_refused(self) -> None:
        """The pointer is allowed; a copy of the value it points at is not, wherever it is attached."""
        component = {'path': 'components/control/platform', 'state': 'selected',
                     'relationship': 'pin-holder',
                     'pin': {'file': 'components/control/platform/versions.json',
                             'key': 'gatus_image'}}
        self.assertEqual([], errors_of(entry_document(components=[dict(component)])))
        quoted = {**component,
                  'conformance_evidence': 'docs/evidence/note.md',
                  'state': 'validated'}
        self.assertEqual([], errors_of(entry_document(components=[quoted])))
        inline = {**component, 'path': 'components/control/sigma',
                  'relationship': 'surface'}
        del inline['pin']
        errors = errors_of(entry_document(components=[inline],
                                          description='Sigma compiles rules with pySigma 1.1.1 here.'))
        self.assertTrue(any_error_matching(errors, 'description', 'dotted version number'), errors)

    def test_the_pin_reference_itself_is_not_a_pin_copy(self) -> None:
        """The positive control: a reference is two strings, neither of which is a version."""
        document = entry_document(components=[{'path': 'components/control/platform',
                                               'state': 'selected', 'relationship': 'pin-holder',
                                               'pin': {'file':
                                                       'components/control/platform/versions.json',
                                                       'key': 'gatus_image'}}])
        self.assertEqual([], errors_of(document))


class StubRefusalTests(unittest.TestCase):
    """An entry that names nothing in the repository is a stub, not an integration."""

    def test_no_component_and_no_module_is_refused(self) -> None:
        document = entry_document(components=[], modules=[])
        errors = errors_of(document)
        self.assertTrue(any_error_matching(errors, 'references no component and no module'), errors)

    def test_an_empty_components_list_alone_is_a_legible_statement(self) -> None:
        document = entry_document(components=[], modules=[{'name': 'host-metrics'}])
        self.assertEqual([], errors_of(document))


class VocabularyPinnedToItsSourceTests(unittest.TestCase):
    """The two vocabularies are copied into the product and pinned here, where they cannot drift."""

    @staticmethod
    def section(text: str, heading: str) -> str:
        start = text.index(heading)
        rest = text[start + len(heading):]
        end = rest.find('\n## ')
        return rest if end < 0 else rest[:end]

    def test_the_validation_states_are_the_three_words_components_md_defines(self) -> None:
        document = (ROOT / 'docs' / 'COMPONENTS.md').read_text(encoding='utf-8')
        section = self.section(document, '## 2. Component matrix')
        self.assertEqual(('selected', 'experimental', 'validated'), manifest.STATES)
        for state in manifest.STATES:
            self.assertIn(f'{state} =', section,
                          f'docs/COMPONENTS.md section 2 no longer defines {state!r}')

    def test_every_component_pin_file_uses_that_vocabulary(self) -> None:
        seen: list[str] = []
        for path in sorted((ROOT / 'components').rglob('versions.json')):
            status = json.loads(path.read_text(encoding='utf-8')).get('status')
            seen.append(f'{path.name}:{status}')
            self.assertIn(status, manifest.STATES,
                          f'{path.relative_to(ROOT)} states {status!r}, which the catalogue does not '
                          'know; either the component or the vocabulary is wrong')
        self.assertTrue(seen, 'no component pin file found to check the vocabulary against')

    def test_the_capabilities_are_architecture_sections_capability_table(self) -> None:
        document = (ROOT / 'docs' / 'ARCHITECTURE.md').read_text(encoding='utf-8')
        section = self.section(document, '## 2. Infrastructure capabilities')
        rows = [line for line in section.splitlines()
                if line.startswith('|') and not line.startswith('|---')]
        labels = [row.split('|')[1].strip() for row in rows][1:]     # drop the header row
        slugged = tuple(sorted(re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-')
                               for label in labels))
        self.assertTrue(labels, 'docs/ARCHITECTURE.md section 2 has no capability table to pin')
        self.assertEqual(slugged, tuple(sorted(manifest.CAPABILITIES)),
                         'the capability vocabulary has drifted from the document that defines it')


if __name__ == '__main__':
    unittest.main()

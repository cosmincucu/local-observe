"""The catalogue registry's refusal set, its reference proofs, and the shipped seeds (module catalog).

Every case is a *load-time* refusal: the registry's only output is entries it proved or an error naming
the field, so this file is the executable form of "an entry cannot lie". Fixtures build a synthetic
checkout (a fake ``components/`` tree) as ``repo_root`` so a reference is proven against a directory the
test owns; the shipped ``examples/catalog`` is walked against the **real** checkout at the end, which is
what keeps the seeds honest as the tree moves under them.

Module fixtures are JSON text in ``.yaml`` files with ``module_parser=json.loads``, the
``tests/test_modules_loader.py`` idiom: the refusal set needs no YAML parser.

``PinOwnershipTests`` and ``OwningKeyResolutionTests`` are the ownership boundary: a pin belongs to the
component that runs the image, and the catalogue has to name *that* component. The reader cannot tell an
owner from a mirror — both files exist and both keys resolve to a string — so the rule is asserted **by
name** against the shipped seed, and one case below proves that the old mirror target still loads clean.
That case is the reason the named assertion exists rather than a trust in a green load.

``ReferenceConfinementTests`` is the boundary added on top of that: every reference an entry names is
confined to the checkout **before** the registry asks a filesystem question about it, because the asking
was the leak — a pin key that did not resolve quoted back the keys of the file it had opened, and a
parent directory that is a symlink, or a ``..`` the old regex let through, made that file somebody
else's. Its negative controls keep the *ordinary* refusals honest: a reference that stays inside and is
merely wrong is reported the way it always was.
"""
import ast
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from local_observe.catalog import manifest as entry_manifest
from local_observe.catalog import registry as registry_module
from local_observe.catalog.registry import CatalogError, CatalogRegistry

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import check_foundation as foundation_checks  # noqa: E402  (the same BANNED_TOKENS the gate enforces)

PLATFORM_VERSIONS = {'status': 'selected', 'gatus_image': 'example.invalid/gatus@sha256:' + 'ab' * 32}
#: The fixture form of the component that owns the engine pin: its own ``versions.json``, whose ``image``
#  key is the authority. It is built beside the platform file above so that a refusal on the owning key
#  can never be a missing file, and so the mirror's survival is visible to the same load.
SYNTHETICS_VERSIONS = {'status': 'experimental', 'image': 'example.invalid/gatus@sha256:' + 'cd' * 32}

#: The owning component, its pin file and the key inside that file, as the shipped seed must name them.
GATUS_OWNER_PATH = 'components/control/synthetics'
GATUS_OWNER_PIN_FILE = 'components/control/synthetics/versions.json'
GATUS_OWNER_PIN_KEY = 'image'
#: The compatibility mirror synthetics component left in the platform file. It still resolves, which is exactly why the
#  ownership rule is asserted by name and not inferred from a load that succeeded.
OLD_MIRROR_REFERENCE = ('components/control/platform/versions.json', 'gatus_image')


class SkipSymlink(Exception):
    """Raised by :func:`make_link` and turned into a skip by the test that asked for the link.

    Only :func:`make_link` raises it, and only on the one Windows privilege gate it names — the
    ``tests/test_anomaly_cursor.py`` precedent, kept local so this suite does not import another
    feature's fixtures.
    """


def make_link(link: Path, target: Path, *, directory: bool = False) -> None:
    """Create *link* pointing at *target*, or raise :class:`SkipSymlink` on the one Windows gate.

    Creating a symbolic link on Windows needs ``SeCreateSymbolicLinkPrivilege``, which a normal account
    does not hold, and the OS says so with ``winerror == 1314``. **Anything else propagates as a
    failure** — an unexpected :class:`OSError` (a filesystem that cannot hold a link, a path that
    cannot be written) is a defect in this suite or in the host, and turning one into a green skip is
    how a confinement test stops testing anything. Every real-link case here also has a deterministic
    injected twin that runs on every platform, so a skip costs coverage of one primitive and not of a
    rule (``docs/testing-standards.md``).
    """
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        if os.name == 'nt' and getattr(exc, 'winerror', None) == 1314:
            raise SkipSymlink from exc
        raise
    except NotImplementedError:
        raise


def inside(candidate: Path, root: Path) -> bool:
    """This suite's own containment oracle: is *candidate* *root* or below it.

    Written independently of ``registry._is_inside`` on purpose — an oracle that calls the function
    under test proves nothing about the paths it is asked about. Both sides are resolved first, because
    the registry hands back resolved paths and a temporary directory's own name is not always one.
    """
    try:
        candidate.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def entry_document(name: str = 'example', **overrides: Any) -> dict[str, Any]:
    """One valid manifest for directory *name*, with any key replaced (``None`` deletes it)."""
    document: dict[str, Any] = {
        'schema_version': 1, 'name': name, 'entry_version': 1,
        'description': 'An optional integration the operator may run beside the stack.',
        'decided_by': 'D-101', 'capabilities': ['container-execution'],
        'components': [{'path': 'components/control/platform', 'state': 'selected',
                        'relationship': 'pin-holder',
                        'pin': {'file': 'components/control/platform/versions.json',
                                'key': 'gatus_image'}}],
        'modules': [],
        'if_disabled': 'Nothing else changes.',
    }
    document.update(overrides)
    return {key: value for key, value in document.items() if value is not None}


def module_document(name: str, *, module_version: int = 1) -> dict[str, Any]:
    """One module document that satisfies module contract's schema, so resolution reaches the revision check.

    The registry resolves a module reference by running ``modules.loader.ModuleLoader`` over the
    operator's directory, which means an invalid module is a refusal before a revision is ever read;
    these fixtures are therefore complete documents, not name stubs. ``applies_to`` only has to parse
    here — the registry names no inventory index, so nothing is resolved against one.
    """
    return {'schema_version': 1, 'name': name, 'module_version': module_version,
            'applies_to': {'any_of': [{'id': 'f47ac10b-58cc-4372-a567-0e02b2c3d479'}]},
            'collection': {'receiver': 'hostmetrics', 'interval_seconds': 30},
            'datapoints': [{'name': 'system.cpu.time', 'unit': 's', 'type': 'counter'}]}


class RegistryFixture(unittest.TestCase):
    """A synthetic checkout: a registry root of entries and a ``components/`` tree they reference."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.registry_root = self.root / 'registry'
        self.registry_root.mkdir()
        self.repo = self.root / 'checkout'
        component = self.repo / 'components' / 'control' / 'platform'
        component.mkdir(parents=True)
        (component / 'versions.json').write_text(json.dumps(PLATFORM_VERSIONS), encoding='utf-8')
        self.modules = self.root / 'modules'
        self.modules.mkdir()

    def write_entry(self, name: str, document: dict[str, Any] | str | bytes | None = None,
                    *, extra: dict[str, str] | None = None) -> Path:
        """Create one entry directory, optionally with unexpected extra files in it."""
        directory = self.registry_root / name
        directory.mkdir(exist_ok=True)
        if document is None:
            document = entry_document(name)
        text = document if isinstance(document, (str, bytes)) else json.dumps(document)
        payload = text if isinstance(text, bytes) else text.encode('utf-8')
        (directory / 'entry.json').write_bytes(payload)
        for filename, body in (extra or {}).items():
            (directory / filename).write_text(body, encoding='utf-8')
        return directory

    def write_module(self, name: str, *, module_version: int = 1) -> Path:
        """One module file the registry can resolve a reference against (JSON text, ``.yaml`` name)."""
        path = self.modules / f'{name}.yaml'
        path.write_text(json.dumps(module_document(name, module_version=module_version)),
                        encoding='utf-8')
        return path

    def registry(self, **kwargs: Any) -> CatalogRegistry:
        kwargs.setdefault('repo_root', self.repo)
        return CatalogRegistry(self.registry_root, **kwargs)

    def errors(self, **kwargs: Any) -> list[str]:
        """The defect list this registry would raise, or ``[]`` when it loads."""
        try:
            self.registry(**kwargs).entries()
        except CatalogError as exc:
            return exc.errors
        return []

    def one_error(self, needle: str, **kwargs: Any) -> str:
        errors = self.errors(**kwargs)
        matches = [error for error in errors if needle in error]
        self.assertTrue(matches, f'{needle!r} not found in {errors}')
        return matches[0]


class DirectoryTests(RegistryFixture):
    """What the registry will walk, and what it refuses to walk."""

    def test_a_root_that_is_not_a_directory_is_a_refusal(self) -> None:
        registry = CatalogRegistry(self.root / 'absent', repo_root=self.repo)
        with self.assertRaises(CatalogError) as caught:
            registry.entries()
        self.assertIn('root: not a directory', str(caught.exception))

    def test_readme_and_contract_are_not_entries(self) -> None:
        self.write_entry('one')
        for name in ('README.md', 'CONTRACT.md'):
            (self.registry_root / name).write_text('prose', encoding='utf-8')
        self.assertEqual(['one'], [entry.name for entry in self.registry().entries()])

    def test_a_stray_file_in_the_root_is_refused_and_not_skipped(self) -> None:
        self.write_entry('one')
        (self.registry_root / 'notes.txt').write_text('dropped here by mistake', encoding='utf-8')
        self.assertIn('notes.txt', self.one_error('refuses to skip a file it was given'))

    def test_a_hidden_directory_is_refused_rather_than_skipped(self) -> None:
        """Unlike the module loader: a published index is counted by its readers, so nothing hides."""
        self.write_entry('one')
        (self.registry_root / '.draft').mkdir()
        self.assertIn('.draft', self.one_error('is not a plain entry directory name'))

    def test_a_directory_that_is_not_a_plain_entry_name_is_refused(self) -> None:
        for name in ('Nested_Dir', 'with space', 'Upper', 'a' * 65):
            with self.subTest(name=name):
                (self.registry_root / name).mkdir()
                self.assertIn(name, self.one_error('is not a plain entry directory name'))
                (self.registry_root / name).rmdir()

    def test_a_registry_past_the_scan_bound_is_refused_not_truncated(self) -> None:
        for index in range(3):
            self.write_entry(f'entry-{index}')
        with mock.patch.object(registry_module, 'MAX_ENTRIES_SCANNED', 2):
            self.assertIn('exceeds the 2-entry bound', self.one_error('bound'))
        self.assertEqual([], self.errors(), 'the bound is a refusal, so nothing changed on disk')

    def test_a_symlinked_entry_directory_is_refused_not_followed(self) -> None:
        """Refused on the predicate, not on a created link: the ``modules.loader`` Windows posture."""
        directory = self.write_entry('one')
        with mock.patch.object(Path, 'is_symlink', lambda self: self == directory):
            self.assertIn('a symlink is not an entry', self.one_error('one'))


class ManifestReadingTests(RegistryFixture):
    """Bounded, strict reading of one ``entry.json``."""

    def test_a_missing_manifest_names_the_entry_and_the_file(self) -> None:
        (self.registry_root / 'empty').mkdir()
        self.assertIn('empty: entry.json: missing manifest', self.one_error('missing manifest'))

    def test_a_symlinked_manifest_is_refused(self) -> None:
        directory = self.write_entry('one')
        manifest_path = directory / 'entry.json'
        with mock.patch.object(Path, 'is_symlink', lambda self: self == manifest_path):
            self.assertIn('a symlink is not followed', self.one_error('one'))

    def test_a_file_inside_an_entry_directory_is_refused(self) -> None:
        """This format references modules from outside the entry, so nothing may live beside it."""
        self.write_entry('one', extra={'host-metrics.yaml': '{}'})
        self.assertIn('host-metrics.yaml', self.one_error('a file inside an entry directory'))

    def test_an_oversized_manifest_is_refused_naming_both_numbers(self) -> None:
        document = entry_document('one')
        document['description'] = 'x' * 20_000
        self.write_entry('one', document)
        with mock.patch.object(registry_module, 'MAX_MANIFEST_BYTES', 4096):
            self.assertIn('bytes exceeds the 4096-byte manifest bound', self.one_error('manifest bound'))

    def test_a_manifest_that_is_not_utf8_is_refused(self) -> None:
        self.write_entry('one', b'\xff\xfe\x00not text')
        self.assertIn('is not UTF-8 text', self.one_error('one'))

    def test_a_manifest_that_is_not_json_is_refused(self) -> None:
        self.write_entry('one', 'name: one\n')
        self.assertIn('parse error', self.one_error('parse error'))

    def test_a_duplicate_key_is_refused_rather_than_resolved_by_precedence(self) -> None:
        text = '{"name": "one", "name": "other", "schema_version": 1}'
        self.write_entry('one', text)
        self.assertIn('duplicate key or a non-finite number', self.one_error('parse error'))

    def test_a_non_finite_number_is_refused(self) -> None:
        self.write_entry('one', '{"name": "one", "entry_version": NaN}')
        self.assertIn('parse error', self.one_error('parse error'))

    def test_a_manifest_that_is_not_an_object_is_refused(self) -> None:
        self.write_entry('one', '[1, 2]')
        self.assertIn('did not parse to an object', self.one_error('one'))

    def test_a_manifest_invalid_against_the_schema_lists_every_field_defect(self) -> None:
        document = entry_document('one')
        document['bogus'] = 1
        document['capabilities'] = ['not-a-capability']
        document['if_disabled'] = 'Two sentences. Like this.'
        self.write_entry('one', document)
        errors = self.errors()
        self.assertTrue(errors, 'one raise carries every defect of this entry')
        for needle in ('bogus', 'capabilities[0]', 'if_disabled'):
            with self.subTest(needle=needle):
                self.assertTrue(any(needle in error for error in errors), errors)
        self.assertTrue(all(error.startswith('one:') for error in errors), errors)


class IdentityTests(RegistryFixture):
    """Name equals directory, and a listing that cannot be complete returns nothing."""

    def test_a_manifest_that_renames_itself_is_refused_naming_both(self) -> None:
        self.write_entry('directory-name', entry_document('different-name'))
        error = self.one_error('must equal its directory name')
        self.assertIn("'different-name'", error)
        self.assertIn("'directory-name'", error)

    def test_no_entry_is_returned_when_any_entry_is_invalid(self) -> None:
        """The no-partial-bind rule: a listing is the whole registry or an error naming every defect."""
        self.write_entry('good')
        bad = entry_document('bad')
        bad['decided_by'] = 'vibes'
        self.write_entry('bad', bad)
        self.write_entry('worse', None)
        (self.registry_root / 'worse' / 'entry.json').write_text('{"name": "worse", "entry_version": 0}',
                                                                encoding='utf-8')
        errors = self.errors()
        joined = ' '.join(errors)
        self.assertTrue(errors, 'an invalid registry raises and names every defect in it')
        self.assertIn('bad: decided_by', joined)
        self.assertIn('worse:', joined)
        self.assertNotIn('good:', joined, 'the valid entry has no defect to report')
        self.assertTrue(all(error.startswith(('bad:', 'worse:')) for error in errors),
                        f'a defect from the valid entry leaked into {errors}')

    def test_the_same_module_claimed_by_two_entries_is_refused(self) -> None:
        """One block, one entry: with no installer to arbitrate, two owners is one ambiguity."""
        self.write_module('host-metrics')
        for name in ('alpha', 'beta'):
            self.write_entry(name, entry_document(name, modules=[{'name': 'host-metrics'}]))
        errors = self.errors(modules=self.modules, module_parser=json.loads)
        joined = ' '.join(errors)
        self.assertIn('is already claimed by entry', joined)
        self.assertIn('beta', joined)
        self.assertIn('alpha', joined)


class EntryReadTests(RegistryFixture):
    """``entry(name)`` and the two browse filters."""

    def test_a_missing_name_is_refused_naming_what_the_root_holds(self) -> None:
        self.write_entry('one')
        with self.assertRaises(CatalogError) as caught:
            self.registry().entry('absent')
        self.assertIn("available entries: ['one']", str(caught.exception))

    def test_a_name_that_is_not_a_plain_entry_name_is_refused_before_any_path_join(self) -> None:
        for name in ('../elsewhere', 'Nested/x', 'Upper', ''):
            with self.subTest(name=name):
                with self.assertRaises(CatalogError) as caught:
                    self.registry().entry(name)
                self.assertIn('is not a plain entry name', str(caught.exception))

    def test_browsing_by_capability_or_state_refuses_a_word_that_does_not_exist(self) -> None:
        self.write_entry('one')
        registry = self.registry()
        self.assertEqual(['one'], [entry.name for entry in registry.by_capability('container-execution')])
        self.assertEqual(['one'], [entry.name for entry in registry.by_state('selected')])
        with self.assertRaises(ValueError):
            registry.by_capability('gpu-hours')
        with self.assertRaises(ValueError):
            registry.by_state('stable')


class ReferenceTests(RegistryFixture):
    """Every reference in a manifest is proven against the checkout, or the entry is refused."""

    def test_a_component_that_does_not_exist_is_refused(self) -> None:
        document = entry_document('one')
        document['components'] = [{'path': 'components/control/absent', 'state': 'selected',
                                   'relationship': 'intake'}]
        self.write_entry('one', document)
        self.assertIn('is not a directory', self.one_error('components[0].path'))

    def test_a_component_path_that_is_a_symlink_is_not_followed(self) -> None:
        target = self.repo / 'components' / 'control' / 'elsewhere'
        target.mkdir(parents=True)
        document = entry_document('one')
        document['components'] = [{'path': 'components/control/elsewhere', 'state': 'selected',
                                   'relationship': 'intake'}]
        self.write_entry('one', document)
        with mock.patch.object(Path, 'is_symlink', lambda self: self == target):
            self.assertIn('is a symlink', self.one_error('components[0].path'))

    def test_a_pin_file_that_does_not_exist_is_refused(self) -> None:
        document = entry_document('one')
        document['components'][0]['pin']['file'] = 'components/control/platform/image-lock.json'
        self.write_entry('one', document)
        self.assertIn('is not a file', self.one_error('pin.file'))

    def test_a_pin_key_that_does_not_resolve_names_where_it_stopped(self) -> None:
        document = entry_document('one')
        document['components'][0]['pin']['key'] = 'images.gatus.image'
        self.write_entry('one', document)
        error = self.one_error('does not resolve')
        self.assertIn("stopped at 'images'", error)
        self.assertIn('gatus_image', error, 'the refusal should show what the file does hold')

    def test_a_pin_key_naming_a_mapping_is_refused_because_a_pin_is_a_string(self) -> None:
        (self.repo / 'components' / 'control' / 'platform' / 'image-lock.json').write_text(
            json.dumps({'locked': {'a': 'x'}}), encoding='utf-8')
        document = entry_document('one')
        document['components'][0]['pin'] = {'file': 'components/control/platform/image-lock.json',
                                           'key': 'locked'}
        self.write_entry('one', document)
        self.assertIn('not to a pinned value', self.one_error('pin.key'))

    def test_a_reference_is_carried_without_the_value_it_points_at(self) -> None:
        """The anti-copy rule, asserted on the returned object rather than in prose."""
        self.write_entry('one')
        entry = self.registry().entries()[0]
        pin = entry.components[0].pin
        self.assertIsNotNone(pin)
        self.assertEqual({'file', 'key'}, set(vars(pin)))
        self.assertNotIn('gatus', json.dumps(entry.as_dict()).replace('gatus_image', ''))

    def test_an_entry_may_under_claim_a_components_own_state(self) -> None:
        (self.repo / 'components' / 'control' / 'platform' / 'versions.json').write_text(
            json.dumps({**PLATFORM_VERSIONS, 'status': 'validated',
                        'note': 'a component claiming more than the entry does'}), encoding='utf-8')
        self.write_entry('one')
        self.assertEqual([], self.errors())

    def test_an_entry_may_not_over_claim_a_components_own_state(self) -> None:
        document = entry_document('one')
        document['components'][0]['state'] = 'experimental'
        document['components'][0]['relationship'] = 'surface'
        del document['components'][0]['pin']
        self.write_entry('one', document)
        self.assertIn('exceeds what components/control/platform claims',
                      self.one_error('components[0].state'))

    def test_a_component_stating_a_status_word_the_vocabulary_lacks_is_named(self) -> None:
        (self.repo / 'components' / 'control' / 'platform' / 'versions.json').write_text(
            json.dumps({'status': 'production-ready'}), encoding='utf-8')
        self.write_entry('one')
        self.assertIn('production-ready', self.one_error('which is not a word'))

    def test_a_validated_claim_needs_its_evidence_file_to_exist(self) -> None:
        document = entry_document('one')
        document['components'][0]['state'] = 'validated'
        document['components'][0]['relationship'] = 'surface'
        del document['components'][0]['pin']
        document['components'][0]['conformance_evidence'] = 'docs/evidence/absent-note.md'
        self.write_entry('one', document)
        self.assertIn('is not a file', self.one_error('conformance_evidence'))

        (self.repo / 'docs' / 'evidence').mkdir(parents=True)
        (self.repo / 'docs' / 'evidence' / 'absent-note.md').write_text('the recipe and its result',
                                                                       encoding='utf-8')
        (self.repo / 'components' / 'control' / 'platform' / 'versions.json').write_text(
            json.dumps({**PLATFORM_VERSIONS, 'status': 'validated'}), encoding='utf-8')
        self.assertEqual([], self.errors(), 'the same entry loads once its evidence is a real file')

    def test_an_inline_pin_is_refused_at_load_naming_the_field(self) -> None:
        """The pin-by-reference rule, end to end: a quoted version never reaches a loaded entry."""
        document = entry_document('one')
        document['description'] = 'The console image is pinned to 1.2.3 by this entry.'
        self.write_entry('one', document)
        self.assertIn('description', self.one_error('dotted version number'))
        self.assertIn('second authority', self.one_error('dotted version number'))


class ReferenceConfinementTests(RegistryFixture):
    """A reference is confined to the checkout before anything is asked about it (the card's boundary).

    Three rules, each from the failing direction: a reference that **climbs** or spells an absolute,
    drive, backslash or control-terminated path is refused as a reference and never reaches the
    filesystem; a reference that is lexically clean but whose **parent resolves outside** ``repo_root``
    is refused before any ``is_file``/``is_dir``/read, and the refusal quotes neither the outside file
    nor the location it resolved to; and neither of those refusals may disturb what a reference that
    *stays inside* and is merely wrong has always reported.

    The tripwire is a read spy, not an absence noticed: :meth:`errors_and_reads` records every
    ``read_bytes`` this registry performs during one load, and the outside file is a real file in a real
    sibling directory, waiting to be opened.
    """

    #: (a whole reference, the phrase its refusal must contain). The first three are the pre-fix
    #  bypasses — every one of them was admitted by the manifest's path regex and joined to a file
    #  outside ``repo_root``, where the registry then asked it questions.
    OUT_OF_TREE_REFERENCES: tuple[tuple[str, str], ...] = (
        ('components/../../sibling-checkout/components/engine/versions.json', 'climb out of it'),
        ('docs/../../sibling-checkout/docs/evidence/canary.md', 'climb out of it'),
        ('components/control/../../sibling-checkout/components/engine/versions.json', 'climb out of it'),
        ('components/.../engine/versions.json', 'nothing but dots'),
        ('components/./engine/versions.json', 'climb out of it'),
        ('components/control/platform/versions.json\n', 'control character'),
        ('docs/evidence/note.md\n', 'control character'),
        ('docs/evidence/note.md\x00', 'control character'),
        ('components\\control\\platform\\versions.json', 'backslash'),
        ('/etc/versions.json', 'absolute'),
        ('C:/windows/versions.json', 'drive letter'),
        ('//server/share/versions.json', 'UNC'),
        ('components//engine/versions.json', 'empty segment'),
        ('components/engine/versions.json/', 'empty segment'),
        ('docs/evidence/note.md.', 'ending in a dot'),
        (' docs/evidence/note.md', 'whitespace'),
    )

    def setUp(self) -> None:
        super().setUp()
        self.sibling = self.root / 'sibling-checkout'
        (self.sibling / 'components' / 'engine').mkdir(parents=True)
        (self.sibling / 'docs' / 'evidence').mkdir(parents=True)
        (self.sibling / 'components' / 'engine' / 'versions.json').write_text(
            json.dumps({'status': 'not-a-state-word', 'outside-canary-key': 'never to be quoted'}),
            encoding='utf-8')
        (self.sibling / 'docs' / 'evidence' / 'canary.md').write_text('a file this entry was not given',
                                                                     encoding='utf-8')

    def document_with(self, field: str, value: str) -> dict[str, Any]:
        """The default fixture entry with one reference replaced by *value* (``pin`` or ``evidence``)."""
        document = entry_document('one')
        if field == 'pin':
            document['components'][0]['pin']['file'] = value
        else:
            document['components'][0]['conformance_evidence'] = value
        return document

    def errors_and_reads(self) -> tuple[list[str], list[Path]]:
        """The defects one load reports, and every path whose bytes it actually opened.

        ``Path.read_bytes`` is the only way this package gets at content, so the recorded list is the
        whole set of files the load opened — the honest form of "never read" is a counted zero.
        """
        opened: list[Path] = []
        read_bytes = Path.read_bytes

        def spy(self: Path) -> bytes:
            opened.append(Path(self))
            return read_bytes(self)

        with mock.patch.object(Path, 'read_bytes', spy):
            errors = self.errors()
        return errors, opened

    def errors_with_resolution_outside(self, attacked: Path, outside: Path) -> list[str]:
        """The defects reported when *attacked* — a well-formed in-root reference — resolves to *outside*.

        The deterministic twin of a symlinked parent, and the reason this card has coverage on a host
        that will not create links: the reference is legal and the *resolution* is the hostile fact, so
        the module's containment check — and not the OS — is what is under test.
        """
        real = registry_module.resolve_reference

        def injected(candidate: Path) -> Path | None:
            return outside if Path(candidate) == attacked else real(candidate)

        with mock.patch.object(registry_module, 'resolve_reference', injected):
            return self.errors()

    def test_every_out_of_tree_reference_shape_is_refused_as_a_reference(self) -> None:
        for value, phrase in self.OUT_OF_TREE_REFERENCES:
            for field in ('pin', 'evidence'):
                with self.subTest(value=repr(value), field=field):
                    self.write_entry('one', self.document_with(field, value))
                    errors = self.errors()
                    field_needle = ('components[0].pin.file' if field == 'pin'
                                    else 'components[0].conformance_evidence')
                    self.assertTrue([error for error in errors
                                     if field_needle in error and phrase in error],
                                    f'{field_needle} + {phrase!r} absent from {errors}')
                    self.assertNotIn('outside-canary-key', ' '.join(errors))

    def test_no_read_ever_reaches_the_sibling_checkout(self) -> None:
        """The tripwire: the outside file exists, is reachable by the reference, and is never opened."""
        for value, _phrase in self.OUT_OF_TREE_REFERENCES:
            for field in ('pin', 'evidence'):
                with self.subTest(value=repr(value), field=field):
                    self.write_entry('one', self.document_with(field, value))
                    errors, opened = self.errors_and_reads()
                    self.assertTrue(errors, 'a refusal was reported, so the loop is not vacuous')
                    self.assertEqual([], [str(path) for path in opened if inside(path, self.sibling)],
                                     'the registry opened a file outside the checkout it was given')

    def test_a_symlinked_parent_outside_the_checkout_is_refused_without_being_read(self) -> None:
        """A real link, on every platform that lets one be made; the injected twin below runs everywhere."""
        link = self.repo / 'components' / 'linked'
        try:
            make_link(link, self.sibling / 'components', directory=True)
        except SkipSymlink:
            self.skipTest('Windows withholds SeCreateSymbolicLinkPrivilege from this test run')
        document = entry_document('one')
        document['components'][0]['path'] = 'components/linked/engine'
        document['components'][0]['pin']['file'] = 'components/linked/engine/versions.json'
        self.write_entry('one', document)
        errors, opened = self.errors_and_reads()
        joined = ' '.join(errors)
        self.assertIn('components[0].path', joined)
        self.assertIn('components[0].pin.file', joined)
        self.assertIn('resolves outside', joined)
        self.assertNotIn('not-a-state-word', joined,
                         'the status word of an outside versions.json was read and quoted back')
        self.assertNotIn('outside-canary-key', joined,
                         'the keys of an outside pin file were read and quoted back')
        self.assertEqual([], [str(path) for path in opened if inside(path, self.sibling)])

    def test_a_reference_that_resolves_outside_the_checkout_is_refused_on_every_platform(self) -> None:
        """The same containment refusal with the resolution injected: no link privilege needed."""
        cases = {
            'components[0].path': (self.repo / 'components' / 'control' / 'platform',
                                   self.sibling / 'components' / 'engine'),
            'components[0].pin.file': (self.repo / 'components' / 'control' / 'platform'
                                       / 'versions.json',
                                       self.sibling / 'components' / 'engine' / 'versions.json'),
        }
        (self.repo / 'docs' / 'evidence').mkdir(parents=True)
        document = entry_document('one')
        document['components'][0]['conformance_evidence'] = 'docs/evidence/note.md'
        cases['components[0].conformance_evidence'] = (
            self.repo / 'docs' / 'evidence' / 'note.md',
            self.sibling / 'docs' / 'evidence' / 'canary.md')
        self.write_entry('one', document)
        for field, (attacked, outside) in cases.items():
            with self.subTest(field=field):
                joined = ' '.join(self.errors_with_resolution_outside(attacked, outside))
                self.assertIn(field, joined)
                self.assertIn('resolves outside', joined)
                self.assertNotIn('outside-canary-key', joined)
                self.assertNotIn('not-a-state-word', joined)

    def test_the_refusal_never_names_the_outside_location_it_resolved_to(self) -> None:
        """A path the entry never wrote is as much a leak as its contents: the refusal stays local.

        ``sibling-checkout`` appears in no reference this document writes — the traversal forms spell
        ``../../sibling-checkout`` for the lexical test, so the case here is the injected resolution.
        """
        attacked = self.repo / 'components' / 'control' / 'platform' / 'versions.json'
        renamed = self.root / 'somewhere-else-entirely' / 'versions.json'
        renamed.parent.mkdir(parents=True)
        renamed.write_text(json.dumps({'a-key-nobody-was-asked-about': 'x'}), encoding='utf-8')
        self.write_entry('one', entry_document('one'))
        joined = ' '.join(self.errors_with_resolution_outside(attacked, renamed))
        self.assertIn('resolves outside', joined)
        self.assertNotIn('somewhere-else-entirely', joined)
        self.assertNotIn('a-key-nobody-was-asked-about', joined)

    def test_final_component_and_pin_symlinks_stay_refused_after_in_root_resolution(self) -> None:
        """A confined target must not erase the existing final-link refusal."""
        original = self.repo / 'components' / 'control' / 'platform'
        alternative = self.repo / 'components' / 'control' / 'alternative'
        alternative.mkdir()
        (alternative / 'versions.json').write_text(json.dumps(PLATFORM_VERSIONS), encoding='utf-8')
        self.write_entry('one', entry_document('one'))
        real_resolve = registry_module.resolve_reference
        real_is_link = Path.is_symlink
        for field, attacked, target in (
                ('components[0].path', original, alternative),
                ('components[0].pin.file', original / 'versions.json', alternative / 'versions.json')):
            with self.subTest(field=field):
                def resolved(candidate: Path) -> Path | None:
                    return target if candidate == attacked else real_resolve(candidate)

                def is_link(candidate: Path) -> bool:
                    return candidate == attacked or real_is_link(candidate)

                with mock.patch.object(registry_module, 'resolve_reference', resolved), \
                        mock.patch.object(Path, 'is_symlink', is_link):
                    errors = self.errors()
                self.assertTrue(any(field in error and 'symlink' in error for error in errors), errors)

    def test_a_proven_in_root_reference_keeps_the_diagnostics_it_always_had(self) -> None:
        """Confinement refuses exits; it does not blunt the ordinary bad-reference report."""
        (self.repo / 'docs' / 'evidence').mkdir(parents=True)
        (self.repo / 'docs' / 'evidence' / 'note.md').write_text('the recipe and its result',
                                                                encoding='utf-8')
        document = entry_document('one')
        document['components'][0]['conformance_evidence'] = 'docs/evidence/note.md'
        self.write_entry('one', document)
        self.assertEqual([], self.errors(), 'a confined reference that exists still loads')

        document['components'][0]['conformance_evidence'] = 'docs/evidence/absent.md'
        self.write_entry('one', document)
        self.assertIn('is not a file', self.one_error('conformance_evidence'))

        document['components'][0]['pin']['key'] = 'images.gatus.image'
        self.write_entry('one', document)
        error = self.one_error('does not resolve')
        self.assertIn("stopped at 'images'", error)
        self.assertIn('gatus_image', error,
                      'an in-root pin file still names the keys it does hold — the reader is confined, '
                      'not blind')

        document['components'][0]['path'] = 'components/control/absent'
        self.write_entry('one', document)
        self.assertIn('is not a directory', self.one_error('components[0].path'))


class ModuleReferenceTests(RegistryFixture):
    """Modules are resolved by running module contract's own loader over the operator's module directory."""

    def test_a_reference_that_resolves_carries_the_revision_found(self) -> None:
        self.write_module('host-metrics', module_version=4)
        document = entry_document('one', modules=[{'name': 'host-metrics', 'min_module_version': 2}])
        self.write_entry('one', document)
        entry = self.registry(modules=self.modules, module_parser=json.loads).entries()[0]
        self.assertEqual(4, entry.modules[0].found_module_version)
        self.assertEqual(2, entry.modules[0].min_module_version)

    def test_a_module_id_that_does_not_exist_is_refused(self) -> None:
        self.write_module('host-metrics')
        document = entry_document('one', modules=[{'name': 'absent-block'}])
        self.write_entry('one', document)
        errors = self.errors(modules=self.modules, module_parser=json.loads)
        self.assertIn("no module named 'absent-block'", errors[0])
        self.assertIn('host-metrics', errors[0], 'the refusal names what the directory does hold')

    def test_a_module_below_the_referenced_revision_is_refused(self) -> None:
        self.write_module('host-metrics', module_version=1)
        document = entry_document('one', modules=[{'name': 'host-metrics', 'min_module_version': 3}])
        self.write_entry('one', document)
        self.assertIn('below the 3 this entry was written against',
                      self.errors(modules=self.modules, module_parser=json.loads)[0])

    def test_an_entry_naming_a_module_without_a_module_directory_is_refused(self) -> None:
        """No fallback state exists for an unresolvable reference: it is refused, not reported."""
        document = entry_document('one', modules=[{'name': 'host-metrics'}])
        self.write_entry('one', document)
        self.assertIn('names no module directory', self.one_error('modules'))

    def test_an_invalid_module_in_the_named_directory_refuses_the_registry(self) -> None:
        """The module contract stays module contract's: its own refusal is surfaced, not re-implemented here."""
        (self.modules / 'broken.yaml').write_text('{not json', encoding='utf-8')
        document = entry_document('one', modules=[{'name': 'host-metrics'}])
        self.write_entry('one', document)
        self.assertIn('could not be loaded', self.errors(modules=self.modules,
                                                        module_parser=json.loads)[0])


class ShippedSeedTests(unittest.TestCase):
    """The three seeds, walked against this checkout: every reference must be a real directory.

    This is the test that fails when a component is renamed, a pin key moves, or a seed starts claiming
    a state the component's own ``versions.json`` does not.
    """

    SEEDS = ('crowdsec-decisions', 'gatus-synthetics', 'portainer-console')

    def setUp(self) -> None:
        self.registry = CatalogRegistry(ROOT / 'examples' / 'catalog', repo_root=ROOT)

    def test_the_registry_holds_exactly_the_named_seeds(self) -> None:
        self.assertEqual(list(self.SEEDS), [entry.name for entry in self.registry.entries()])

    def test_every_seed_names_a_real_component_directory_or_module(self) -> None:
        for entry in self.registry.entries():
            with self.subTest(entry=entry.name):
                self.assertTrue(entry.components or entry.modules,
                                'a seed that names nothing in this repository is a stub')
                for component in entry.components:
                    self.assertTrue((ROOT / component.path).is_dir(),
                                    f'{entry.name} references {component.path}, which is not here')
                for reference in entry.modules:
                    self.assertTrue(reference.found_module_version >= 1)

    def test_every_seed_states_only_what_the_tree_can_support(self) -> None:
        for entry in self.registry.entries():
            with self.subTest(entry=entry.name):
                self.assertRegex(entry.decided_by, entry_manifest.DECISION_SHAPE.pattern,
                                 'a seed must be traceable to a decision in the registers')
                for component in entry.components:
                    self.assertIn(component.state, entry_manifest.STATES)
                    if component.state == entry_manifest.VALIDATED:
                        self.assertTrue((ROOT / component.conformance_evidence).is_file())
                for capability in entry.capabilities:
                    self.assertIn(capability, entry_manifest.CAPABILITIES)

    def test_the_gatus_seed_points_at_the_pin_that_owns_the_engine_image(self) -> None:
        entry = self.registry.entry('gatus-synthetics')
        pin = entry.components[0].pin
        document = json.loads((ROOT / pin.file).read_text(encoding='utf-8'))
        self.assertTrue(document[pin.key].startswith('twinproduction/gatus@'))

    def test_no_seed_carries_a_module_reference_because_no_block_ships_for_them(self) -> None:
        """docs/COMPONENTS.md section 3 says none of these three ships a module; the seeds agree."""
        for entry in self.registry.entries():
            self.assertEqual((), entry.modules, f'{entry.name} claims a module that does not exist')

    def test_the_seeds_keep_every_banned_token_out_of_their_files(self) -> None:
        """The same list ``check_foundation.check_private_references`` enforces, asserted directly."""
        files = sorted((ROOT / 'examples' / 'catalog').rglob('*'))
        self.assertTrue([path for path in files if path.is_file()], 'no seed files to scan')
        for path in files:
            if not path.is_file():
                continue
            body = path.read_text(encoding='utf-8')
            for token in foundation_checks.BANNED_TOKENS:
                with self.subTest(path=path.name, token=token):
                    self.assertNotIn(token, body)

    def test_no_seed_file_is_a_symlink_or_a_stray(self) -> None:
        root = ROOT / 'examples' / 'catalog'
        for directory in sorted(root.iterdir()):
            self.assertFalse(directory.is_symlink())
            if not directory.is_dir():
                self.assertIn(directory.name, registry_module.IGNORED_NAMES,
                              f'{directory} is a file loose in a registry root')
                continue
            for child in sorted(directory.iterdir()):
                self.assertIn(child.name, ('entry.json', *registry_module.IGNORED_NAMES),
                              f'{child} is content a reader would skip')


class PinOwnershipTests(unittest.TestCase):
    """Which component owns the Gatus image pin, asserted on the shipped seed through the real reader.

    The seed used to name ``components/control/platform`` because that file held a copy of the engine
    pin. The authority moved to ``components/control/synthetics`` and the platform key stayed behind as
    a compatibility mirror — and a reference check cannot tell those two situations apart: both files
    exist, both keys resolve to a string, so **an entry pointed at the mirror loads green** (proved in
    :class:`OwningKeyResolutionTests`). Ownership therefore has to be stated as a name, against the
    shipped seed and the shipped tree, in the one place a moved-back entry fails.
    """

    def setUp(self) -> None:
        self.registry = CatalogRegistry(ROOT / 'examples' / 'catalog', repo_root=ROOT)
        self.entry = self.registry.entry('gatus-synthetics')

    def components_of(self, name: str) -> list[tuple[str, str, dict[str, Any] | None]]:
        """``(path, relationship, pin pointer)`` for one shipped seed, and no pin value in it."""
        return [(component.path, component.relationship,
                 component.pin.as_dict() if component.pin else None)
                for component in self.registry.entry(name).components]

    def test_the_seed_names_the_owning_component_and_its_own_pin_key(self) -> None:
        self.assertEqual(1, len(self.entry.components),
                         'one engine has one owning component in this tree; a second component '
                         'reference would be a second claim about who the pin belongs to')
        component = self.entry.components[0]
        self.assertEqual(GATUS_OWNER_PATH, component.path)
        self.assertIsNotNone(component.pin, 'a pin-bearing relationship must carry a pointer')
        self.assertEqual({'file': GATUS_OWNER_PIN_FILE, 'key': GATUS_OWNER_PIN_KEY},
                         component.pin.as_dict(),
                         'the pointer names the file and key that own the engine image')
        self.assertIn(component.relationship, entry_manifest.PIN_BEARING,
                      'the relationship is the one that obliges a pin pointer; "surface" or "intake" '
                      'here would drop the pin the entry exists to name')

    def test_the_key_the_seed_names_carries_the_engine_image_itself(self) -> None:
        """The pointer is proven by the reader; this proves it points at the *engine's* value."""
        document = json.loads((ROOT / GATUS_OWNER_PIN_FILE).read_text(encoding='utf-8'))
        key = self.entry.components[0].pin.key
        self.assertEqual(GATUS_OWNER_PIN_KEY, key)
        self.assertTrue(document[key].startswith('twinproduction/gatus@'),
                        f'{GATUS_OWNER_PIN_FILE}:{key} names no engine image; the entry would be '
                        'pointing at a field it is not about')

    def test_no_seed_pin_reads_the_old_platform_mirror(self) -> None:
        """The ownership regression, asserted over every seed rather than only over this one.

        The mirror exists because a seed read it; a second seed doing the same would be the same defect
        one step further along, so the guard walks the whole shipped registry. The platform directory
        stays admissible as a *component* (`crowdsec-decisions` names it as an intake) and is refused
        only as the source of a pin.
        """
        for entry in self.registry.entries():
            for component in entry.components:
                with self.subTest(entry=entry.name, path=component.path):
                    if component.pin is not None:
                        self.assertNotEqual(OLD_MIRROR_REFERENCE, (component.pin.file, component.pin.key),
                                            'a seed names the compatibility mirror as its pin; the '
                                            'owning component is ' + GATUS_OWNER_PATH + ' and the entry '
                                            'must name that file and key instead')
        self.assertNotIn('components/control/platform',
                         [component.path for component in self.entry.components],
                         'the platform component is the mirror holder this entry used to describe; it is '
                         'not the engine this entry touches')

    def test_the_compatibility_mirror_still_exists_and_still_agrees_with_the_owner(self) -> None:
        """This move deletes no pin and weakens no equality guard; the catalogue simply stops depending on it."""
        owner = json.loads((ROOT / GATUS_OWNER_PIN_FILE).read_text(encoding='utf-8'))
        mirror = json.loads((ROOT / OLD_MIRROR_REFERENCE[0]).read_text(encoding='utf-8'))
        self.assertIn(OLD_MIRROR_REFERENCE[1], mirror,
                      'the compatibility key was deleted, and deleting a pin is a decision of its own: '
                      'this file and tests/test_gatus_component.py both still say the two copies agree')
        self.assertEqual(owner[GATUS_OWNER_PIN_KEY], mirror[OLD_MIRROR_REFERENCE[1]],
                         'the mirror is worth exactly as much as its equality with the owning key '
                         '(tests/test_gatus_component.py keeps that guard from the component side)')

    def test_the_other_seeds_name_what_they_always_named(self) -> None:
        """One entry's ownership moved; nobody re-tidied the catalogue on the way past."""
        for name, expected in (('crowdsec-decisions', [('components/control/platform', 'intake', None)]),
                               ('portainer-console', [('components/control/homepage', 'surface', None)])):
            with self.subTest(entry=name):
                self.assertEqual(expected, self.components_of(name))


class OwningKeyResolutionTests(RegistryFixture):
    """The resolver follows the pointer it was given: the owning key has no substitute and no fallback.

    The fixture checkout carries both files, which is the whole point of it. When the owning key is
    missing or misspelled the registry must refuse *even though a string holding the same engine image
    sits in that very file under the old mirror's name* — a resolver that reached for it would be
    choosing an authority for itself, which is the defect the ownership rule exists to stop. The last
    case runs the control the other way: the mirror target resolves cleanly, so no reference check can
    report an ownership error and ``PinOwnershipTests`` is the only witness.
    """

    def setUp(self) -> None:
        super().setUp()
        owner = self.repo / 'components' / 'control' / 'synthetics'
        owner.mkdir(parents=True)
        self.owner_file = owner / 'versions.json'
        self.owner_file.write_text(json.dumps(SYNTHETICS_VERSIONS), encoding='utf-8')

    def owner_document(self, *, path: str = GATUS_OWNER_PATH, file: str = GATUS_OWNER_PIN_FILE,
                       key: str = GATUS_OWNER_PIN_KEY,
                       relationship: str = 'engine') -> dict[str, Any]:
        """One entry whose single component names *path* and pins through *file* under *key*."""
        document = entry_document('one')
        document['components'] = [{'path': path, 'state': 'selected', 'relationship': relationship,
                                   'pin': {'file': file, 'key': key}}]
        return document

    def test_the_owning_component_and_key_load_and_carry_no_value(self) -> None:
        self.write_entry('one', self.owner_document())
        self.assertEqual([], self.errors(), 'the owning pointer resolves in a matching checkout')
        entry = self.registry().entries()[0]
        self.assertEqual({'file': GATUS_OWNER_PIN_FILE, 'key': GATUS_OWNER_PIN_KEY},
                         entry.components[0].pin.as_dict())
        self.assertNotIn('example.invalid', json.dumps(entry.as_dict()),
                         'the pointer resolves; the value it resolves to never travels with the entry')

    def test_a_missing_owning_key_refuses_rather_than_reading_the_mirror_key_in_the_same_file(self) -> None:
        """No fallback: the value the entry wanted is in that file, under the other name, and unused."""
        self.owner_file.write_text(json.dumps({'status': 'experimental',
                                               'gatus_image': SYNTHETICS_VERSIONS['image']}),
                                   encoding='utf-8')
        self.write_entry('one', self.owner_document())
        error = self.one_error('does not resolve')
        self.assertIn('components[0].pin.key', error)
        self.assertIn(GATUS_OWNER_PIN_KEY, error)
        with self.assertRaises(CatalogError):
            self.registry().entries()
        self.assertEqual(SYNTHETICS_VERSIONS['image'],
                         json.loads(self.owner_file.read_text(encoding='utf-8'))['gatus_image'],
                         'the refusal is not an empty file: an entry that fell back to the mirror name '
                         'would have loaded, and this one did not')

    def test_a_wrong_owning_key_refuses_without_a_substitute_being_chosen(self) -> None:
        for key in ('gatus_image', 'gatus', 'image.digest'):
            with self.subTest(key=key):
                self.write_entry('one', self.owner_document(key=key))
                errors = self.errors()
                matches = [error for error in errors if 'does not resolve' in error]
                self.assertTrue(matches, errors)
                self.assertIn('components[0].pin.key', matches[0])
                self.assertIn(key, matches[0], 'the refusal names the key the entry wrote, not the one '
                                               'it settled for')
                self.assertEqual([], [error for error in errors if 'components[0].path' in error],
                                 'the owning component exists; only the key it was asked for is missing')

    def test_an_entry_pointing_at_the_old_mirror_loads_which_is_why_ownership_is_named(self) -> None:
        """The negative control main reverts against: resolution is not ownership.

        Both forms of the old target — the pointer alone, and the component with it — are accepted here,
        because the platform file and its ``gatus_image`` key exist and hold a string. A green registry
        therefore says nothing about who owns the pin; the shipped-seed assertions above are what carry
        that rule, and reverting the entry to this shape fails there and nowhere else.
        """
        forms = {
            'pointer only': self.owner_document(file=OLD_MIRROR_REFERENCE[0],
                                                key=OLD_MIRROR_REFERENCE[1]),
            'component and pointer': self.owner_document(path='components/control/platform',
                                                        file=OLD_MIRROR_REFERENCE[0],
                                                        key=OLD_MIRROR_REFERENCE[1]),
        }
        for label, document in forms.items():
            with self.subTest(form=label):
                self.write_entry('one', document)
                self.assertEqual([], self.errors(),
                                 'this is the shape a moved-back seed takes, and the reader cannot see '
                                 'the difference')


class NoExecutionBoundaryTests(unittest.TestCase):
    """Task 4 as a gate: this package reads files and refuses. It never runs what it reads."""

    FORBIDDEN_BARE_CALLS = ('exec', 'eval', '__import__', 'globals', 'locals')
    FORBIDDEN_ATTRIBUTE_CALLS = ('system', 'popen', 'check_output', 'exec_module', 'execv', 'execve',
                                 'spawn', 'clone', 'fetch', 'checkout')
    FORBIDDEN_MODULES = ('importlib', 'subprocess', 'shutil', 'ctypes', 'tempfile', 'pip', 'git')

    def setUp(self) -> None:
        self.sources = sorted((ROOT / 'local_observe' / 'catalog').glob('*.py'))
        self.assertTrue(self.sources, 'the catalogue package has no modules to check')

    def test_the_package_ships_no_importer_installer_or_writer(self) -> None:
        names = {path.name for path in self.sources}
        self.assertEqual({'__init__.py', 'manifest.py', 'registry.py'}, names)

    def test_no_module_executes_or_spawns_anything(self) -> None:
        for path in self.sources:
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    called = node.func
                    if isinstance(called, ast.Name):
                        self.assertNotIn(called.id, self.FORBIDDEN_BARE_CALLS,
                                         f'{path.name}:{node.lineno} calls {called.id}()')
                    elif isinstance(called, ast.Attribute):
                        self.assertNotIn(called.attr, self.FORBIDDEN_ATTRIBUTE_CALLS,
                                         f'{path.name}:{node.lineno} calls .{called.attr}()')
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    origin = getattr(node, 'module', None) or ''
                    for alias in getattr(node, 'names', ()):
                        module = f'{origin}.{alias.name}' if origin else alias.name
                        head = module.split('.')[0]
                        self.assertNotIn(head, self.FORBIDDEN_MODULES,
                                         f'{path.name}:{node.lineno} imports {module}')

    def test_no_file_is_written_by_any_path_in_the_package(self) -> None:
        """Every open in the package is a read; a write would be an installer arriving quietly."""
        for path in self.sources:
            source = path.read_text(encoding='utf-8')
            for marker in ('.write_text', '.write_bytes', 'open(', 'os.replace', 'os.makedirs',
                           'mkdir(', 'remove(', 'unlink('):
                with self.subTest(path=path.name, marker=marker):
                    self.assertNotIn(marker, source)

    def test_the_package_exposes_no_install_or_activate_verb(self) -> None:
        import local_observe.catalog as catalog_package

        public = {name.lower() for name in catalog_package.__all__}
        for verb in ('import_entry', 'install', 'activate', 'importer', 'enable'):
            self.assertNotIn(verb, public)
        self.assertFalse(hasattr(catalog_package, 'CatalogImporter'))


if __name__ == '__main__':
    unittest.main()

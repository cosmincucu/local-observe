"""Read a directory of catalogue entries: all-or-nothing, referenced, and never executed (module catalog).

"Git-backed" keeps v0.1's meaning exactly (`legacy:catalog/registry.py`): **a plain directory versioned by
the repository around it, with no git operation anywhere in this file**. No fetch, no clone, no
`git log`, no network. An entry is a file the surrounding review process already versioned.

Two disciplines are ported intact, because they are the reason a bad entry is a build error rather
than a surprise at install time:

* **The name is the directory.** An entry's ``name`` must equal its directory name, so entry names are
  unique by construction and one glance at a registry root lists it. A manifest that renames itself is
  refused, naming both names.
* **Validate every entry before returning any.** :meth:`CatalogRegistry.entries` accumulates the
  defects of *every* entry and raises one :class:`CatalogError` naming each one, so a first draft of a
  registry is one round trip and not a walk through six failures; a registry that raised has handed
  back no entries at all. This is `modules.loader.load()`'s rule, imported as a habit and — for the
  module side — imported as code too: module references are resolved by running
  :class:`modules.loader.ModuleLoader` over the operator's module directory, so nothing in this
  package re-implements what a valid module is.

What an entry can do in this build — the boundary, stated plainly
-----------------------------------------------------------------
**Nothing except make this registry refuse.** No code in an entry is imported, no module file is
copied anywhere, no container is started, no path is written, and **executing or installing an entry is
not implemented here**: v0.1's `importer.py` (243 lines of staging, an `installed.json` index and
in-place version replacement) is deliberately not ported. This package validates the *manifest* of an
importable bundle and stops. That sentence belongs in this docstring rather than in a future release
note because the alternative is an operator reading a catalogue as an installer and discovering
otherwise at the moment something is activated (see :mod:`.manifest` for why a manifest still needs a
`entry_version` when nothing orders it).

The refusals, which are the whole interface
-------------------------------------------
Every one names the offending field. Full list and fixtures: `tests/test_catalog_registry.py`.

* root missing, root not a directory, or more than :data:`MAX_ENTRIES_SCANNED` children;
* an entry directory named something :data:`manifest.NAME_SHAPE` will not hold, a symlink at either
  the entry directory or its manifest, or a file in an entry directory other than ``entry.json`` and
  the two ignored documents — the `modules.loader` defect class: a file a reader skipped is content
  they think is shipped;
* a manifest that is missing, unreadable, not UTF-8, over :data:`MAX_MANIFEST_BYTES`, not JSON, JSON
  with a key stated twice or with `NaN`/`Infinity`, or invalid against :mod:`.manifest`;
* a ``name`` that is not its directory name;
* a referenced component directory that does not exist, a pin whose file or key does not resolve, an
  evidence path that is not a file, a module id that no module in the named directory declares, and a
  module whose ``module_version`` is below the referenced minimum; and
* a manifest reference — a component path, a pin file or an evidence path — that is not a *lexical*
  path inside a checkout (absolute, drive/UNC/device form, backslash separator, empty or repeated
  separator, a ``.``/``..``/all-dots segment, a segment ending in a dot, a control terminator), or
  whose **resolved** path is not inside the configured ``repo_root`` (a symlinked or junctioned
  parent). Both halves run **before** any ``is_file``, ``is_dir`` or read, because the asking
  is itself the leak: :meth:`_check_pin` names the keys of the file a pointer reached and
  :meth:`_component_state` names the status word it read, so an outside file reached through ``..`` or
  through a link once put its own contents into a build log;

There is **no log line** in this module, unlike :mod:`.modules.loader`: the loader logs because it can
load something while reporting a proof it could not make (`unverified`, `unchecked`). A catalogue entry
has no such state — every gap above is a raise — so a WARNING here would be the sound of nothing.
"""
from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from local_observe.modules.loader import ModuleLoadError, ModuleLoader, parse_yaml

from . import manifest as entry_manifest

#: The manifest filename, kept from v0.1 so an existing registry directory needs no rename.
MANIFEST_FILENAME = 'entry.json'
#: Files a registry root may hold that are not entries. The same pair `modules.loader` ignores.
IGNORED_NAMES = ('README.md', 'CONTRACT.md')
#: Entries scanned before the registry gives up. A registry past this is not a catalogue an operator
#  read; it is a generated tree, and a generated tree is a card with its own review path.
MAX_ENTRIES_SCANNED = 128
#: One manifest's ceiling. An entry names references and three sentences of prose; v0.1's seeds were
#  ~4 KiB because they carried whole inline modules, which this format refuses.
MAX_MANIFEST_BYTES = 16_384
#: A pin file read to resolve one key. `components/control/ai/versions.json` is the largest here at
#  ~7 KiB; 256 KiB is room for a component register that grows, and a refusal beats a walk.
MAX_PIN_FILE_BYTES = 262_144
NAME_SHAPE = entry_manifest.NAME_SHAPE
#: The validation states ordered by what they promise, so an entry may under-claim a component and
#  never over-claim it. Same tuple as the vocabulary, in the same order, so the two cannot disagree.
_STATE_ORDER = entry_manifest.STATES

#: The checkout the ``components/`` and ``docs/`` references inside a manifest are relative to: the
#  product checkout this package was imported from. An operator registry pointing at its own tree
#  passes ``repo_root=`` explicitly rather than inheriting this.
DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]


def _echo(value: Any) -> str:
    """Quote *value* in a refusal only if it is short and free of separators worth escaping."""
    return (repr(value) if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:/ -]{0,64}', value)
            else "'?'")


def resolve_reference(candidate: Path) -> Path | None:
    """Resolve symlinks and supported junctions in *candidate*, or return ``None`` on refusal.

    Filesystem mounts which retain their lexical path are not detected by this check.

    The one place this module asks the filesystem what a path **is** rather than what it contains, and
    therefore the seam a test substitutes when it cannot create the resolution it means to prove (a
    symlinked parent on a host that withholds ``SeCreateSymbolicLinkPrivilege`` — the
    ``platform/anomaly_cursor.symlink_present`` precedent, and ``docs/testing-standards.md``). ``None``
    is the platform refusing to answer at all: a symlink loop, or a path it will not name.
    """
    try:
        return candidate.resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _is_inside(candidate: Path, root: Path) -> bool:
    """Whether *candidate* is **strictly below** *root*, compared the way this platform compares paths.

    Segment by segment, not as a string prefix: ``/opt/checkout`` must not contain
    ``/opt/checkout-other``. Normalize each component with this platform's path-case rules.
    Strictly below is the rule a manifest states — every
    reference has at least one segment under ``components/``, ``docs/``, ``examples/`` or
    ``local_observe/`` — so a reference that resolves *to* the checkout root is refused with the rest,
    rather than being read as a component that happens to be the whole tree.
    """
    parts = [os.path.normcase(part) for part in candidate.parts]
    boundary = [os.path.normcase(part) for part in root.parts]
    return len(parts) > len(boundary) and parts[:len(boundary)] == boundary


class _Rejected(Exception):
    """Internal signal for what ``json`` does not refuse by itself: a duplicate key, NaN, Infinity."""


class CatalogError(Exception):
    """A catalogue entry, or the registry holding it, is not admissible.

    Carries the offending subject (an entry name, or the registry root) and one sentence per defect,
    each naming the field. A raise hands back no entries: see the module docstring.
    """

    def __init__(self, subject: str, errors: list[str]) -> None:
        self.subject = subject
        self.errors = list(errors)
        super().__init__(f"catalog entry {self.subject!r} is invalid: " + '; '.join(self.errors))


@dataclass(frozen=True)
class Pin:
    """A pointer into the one file that owns a version pin — never the pin's value.

    The value is deliberately not carried: an entry that held the resolved digest could go stale
    exactly like one that quoted it, and the point of referencing `components/**/versions.json` is
    that a pin moves in one file with a reason and a rollback line.
    """

    file: str
    key: str

    def as_dict(self) -> dict[str, Any]:
        """Return the pointer as JSON-safe data, with no value in it."""
        return {'file': self.file, 'key': self.key}


@dataclass(frozen=True)
class ComponentRef:
    """One ``components/<plane>/<name>`` reference, with its state and how it relates to the entry."""

    path: str
    state: str
    relationship: str
    pin: Pin | None = None
    conformance_evidence: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return the reference without resolution detail; ``state`` is the claim, and it is kept."""
        return {'path': self.path, 'state': self.state, 'relationship': self.relationship,
                'pin': self.pin.as_dict() if self.pin else None,
                'conformance_evidence': self.conformance_evidence}


@dataclass(frozen=True)
class ModuleRef:
    """A reference to an module contract module, and the revision this entry was written against.

    ``found_module_version`` is what the operator's module directory actually held at load time, so an
    entry cannot silently mean "whatever revision is loaded now".
    """

    name: str
    min_module_version: int
    found_module_version: int

    def as_dict(self) -> dict[str, Any]:
        """Return the reference and what it resolved to."""
        return {'name': self.name, 'min_module_version': self.min_module_version,
                'found_module_version': self.found_module_version}


@dataclass(frozen=True)
class CatalogEntry:
    """One validated entry: its manifest fields, its resolved references, and its directory path."""

    name: str
    entry_version: int
    description: str
    decided_by: str
    if_disabled: str
    capabilities: tuple[str, ...]
    components: tuple[ComponentRef, ...]
    modules: tuple[ModuleRef, ...]
    path: str

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-safe form a report, a portal or a build step can carry."""
        return {'name': self.name, 'entry_version': self.entry_version, 'description': self.description,
                'decided_by': self.decided_by, 'if_disabled': self.if_disabled,
                'capabilities': list(self.capabilities),
                'components': [component.as_dict() for component in self.components],
                'modules': [module.as_dict() for module in self.modules], 'path': self.path}

    def needs(self, capability: str) -> bool:
        """Whether this entry declares *capability* (exact match, case-sensitive by design).

        Case-sensitive because :data:`entry_manifest.CAPABILITIES` is a closed vocabulary, not free
        text: an entry either names the capability or it does not, and folding case here would be the
        first step towards a manifest spelling it two ways.
        """
        return capability in self.capabilities


@dataclass
class CatalogRegistry:
    """List, get and filter the entries under one registry root.

    Args:
        root: The registry directory. One immediate subdirectory is one entry.
        modules: The operator's module directory that ``modules`` references resolve against — the
            same directory :class:`modules.loader.ModuleLoader` reads. Omit it and an entry that
            names a module is **refused**, not reported as unresolved: a reference nobody can check is
            a promise nobody made. An entry that names none (which is what every seed here does,
            because `docs/COMPONENTS.md` §3 states none of those integrations ships a module) loads
            with no module references and no gap to report.
        repo_root: The checkout ``components/`` paths, pin files and evidence paths are relative to,
            **and the boundary every one of them is confined to**: a reference is resolved and refused
            if the answer is not inside this directory (see :meth:`_confined`). Defaults to the checkout
            this package lives in; pass the operator's own checkout to check an operator registry
            against the tree its pins name. Containment is relative to this directory — what it is a
            symlink or a mount on top of is the operator's provisioning, not something this reader can
            see through.
        module_parser: Passed straight to ``ModuleLoader`` so the refusal set runs without PyYAML.

    Raises:
        CatalogError: From any read method, naming the entry or root and every defect found.
    """

    root: Path | str
    modules: Path | str | None = None
    repo_root: Path | str | None = None
    module_parser: Callable[[str], dict[str, Any]] = parse_yaml
    _module_versions: dict[str, int] | None = field(default=None, init=False, repr=False)

    # -- public reads ------------------------------------------------------

    def entries(self) -> list[CatalogEntry]:
        """Every entry under the root, sorted by name; all-or-nothing.

        A registry with three bad entries reports nine defects in one raise and returns nothing, so a
        half-valid listing cannot be rendered as a catalogue.
        """
        entries: list[CatalogEntry] = []
        problems: list[str] = []
        claimed: dict[str, str] = {}
        for directory in self._entry_directories():
            try:
                entry = self._read_entry(directory)
            except CatalogError as exc:
                problems.extend(f'{directory.name}: {error}' for error in exc.errors)
                continue
            for reference in entry.modules:
                owner = claimed.get(reference.name)
                if owner is not None and owner != entry.name:
                    problems.append(f'{entry.name}: modules reference {reference.name!r} is already '
                                    f'claimed by entry {owner!r}; one block, one entry')
                claimed.setdefault(reference.name, entry.name)
            entries.append(entry)
        if problems:
            raise CatalogError(str(self.root), problems)
        return entries

    def entry(self, name: str) -> CatalogEntry:
        """One entry by name; a missing name is refused naming what the root does hold."""
        if not isinstance(name, str) or not NAME_SHAPE.fullmatch(name):
            raise CatalogError(str(name), [f'name: {_echo(name)} is not a plain entry name '
                                           f'(the shape is {NAME_SHAPE.pattern})'])
        directory = Path(self.root) / name
        if not directory.is_dir() or directory.is_symlink():
            root = Path(self.root)
            if not root.is_dir():
                raise CatalogError(name, [f'name: registry root {str(root)!r} is not a directory, so '
                                          f'no entry could be named'])
            available = sorted(child.name for child in self._children()
                               if child.is_dir() and not child.is_symlink())
            raise CatalogError(name, [f'name: no such entry; available entries: {available}'])
        return self._read_entry(directory)

    def by_capability(self, capability: str) -> list[CatalogEntry]:
        """Entries declaring *capability* — the browse axis component independence's wording implies (capability, not
        v0.1's ``device_class``, which was an SNMP taxonomy this product has no use for)."""
        if capability not in entry_manifest.CAPABILITIES:
            raise ValueError(f'unknown capability: {capability!r}; this catalogue knows '
                             f'{", ".join(entry_manifest.CAPABILITIES)}')
        return [entry for entry in self.entries() if entry.needs(capability)]

    def by_state(self, state: str) -> list[CatalogEntry]:
        """Entries with at least one component reference in validation *state*."""
        if state not in entry_manifest.STATES:
            raise ValueError(f'unknown validation state: {state!r}; the vocabulary is '
                             f'{", ".join(entry_manifest.STATES)} (docs/COMPONENTS.md section 2)')
        return [entry for entry in self.entries()
                if any(component.state == state for component in entry.components)]

    def summary(self) -> dict[str, Any]:
        """The whole registry as one JSON-safe record, for a report or a build log."""
        entries = self.entries()
        return {'root': str(self.root), 'entries': [entry.as_dict() for entry in entries],
                'capabilities': sorted({capability for entry in entries
                                        for capability in entry.capabilities}),
                'states': sorted({component.state for entry in entries
                                  for component in entry.components})}

    # -- the directory -----------------------------------------------------

    @property
    def repo(self) -> Path:
        """The checkout a manifest's root-relative references resolve against."""
        return Path(self.repo_root) if self.repo_root is not None else DEFAULT_REPO_ROOT

    def _children(self) -> list[Path]:
        return sorted(Path(self.root).iterdir(), key=lambda item: item.name)

    def _entry_directories(self) -> list[Path]:
        """Return the entry directories, refusing anything else in the root.

        Unlike :meth:`modules.loader.ModuleLoader._directory`, a dot-prefixed name is **refused and not
        skipped**: a module directory is the operator's own workspace, where an editor's droppings are
        noise, while a registry root is a published index whose readers count its entries, so a hidden
        directory is a name that is not a plain entry name.
        """
        root = Path(self.root)
        if not root.is_dir():
            raise CatalogError(str(root), ['root: not a directory, so no entry could be read'])
        children = self._children()
        if len(children) > MAX_ENTRIES_SCANNED:
            raise CatalogError(str(root), [f'root: {len(children)} children exceeds the '
                                           f'{MAX_ENTRIES_SCANNED}-entry bound; the registry refuses to '
                                           'scan what it cannot show a reader'])
        problems: list[str] = []
        directories: list[Path] = []
        for child in children:
            if child.is_symlink():
                # The one filesystem question asked about an entry, refused rather than followed: a
                # link out of a registry root points at content the registry was not given, and the
                # name it publishes would not say so.
                problems.append(f'{child.name}: a symlink is not an entry and is not followed')
            elif child.is_dir():
                if not NAME_SHAPE.fullmatch(child.name):
                    problems.append(f'{child.name}: is not a plain entry directory name (the shape is '
                                    f'{NAME_SHAPE.pattern}; a nested tree is not an entry either)')
                else:
                    directories.append(child)
            elif child.name in IGNORED_NAMES and child.is_file():
                continue
            else:
                problems.append(f'{child.name}: not an entry directory and not one of '
                                f'{", ".join(IGNORED_NAMES)}; the registry refuses to skip a file it '
                                'was given')
        if problems:
            raise CatalogError(str(root), problems)
        return directories

    def _read_entry(self, directory: Path) -> CatalogEntry:
        """Read, validate and resolve one entry directory."""
        manifest = self._read_manifest(directory)
        result = entry_manifest.validate(manifest)
        if not result.ok:
            raise CatalogError(directory.name, list(result.errors))
        if manifest['name'] != directory.name:
            raise CatalogError(directory.name, [
                f'name: manifest name {manifest["name"]!r} must equal its directory name '
                f'{directory.name!r}; names are unique by construction or they are not names'])

        problems: list[str] = []
        problems.extend(self._check_components(manifest))
        problems.extend(self._check_modules(manifest))
        if problems:
            raise CatalogError(directory.name, problems)

        components = tuple(ComponentRef(
            path=item['path'], state=item['state'], relationship=item['relationship'],
            pin=Pin(item['pin']['file'], item['pin']['key']) if item.get('pin') else None,
            conformance_evidence=item.get('conformance_evidence')) for item in manifest['components'])
        modules = tuple(ModuleRef(
            name=item['name'],
            min_module_version=item.get('min_module_version', 1),
            found_module_version=self._available_modules()[item['name']]) for item in manifest['modules'])
        return CatalogEntry(name=manifest['name'], entry_version=manifest['entry_version'],
                            description=manifest['description'], decided_by=manifest['decided_by'],
                            if_disabled=manifest['if_disabled'],
                            capabilities=tuple(manifest['capabilities']), components=components,
                            modules=modules, path=str(directory))

    # -- bounded reading ---------------------------------------------------

    def _read_manifest(self, directory: Path) -> dict[str, Any]:
        """Read one entry directory's manifest: bounded, strict JSON, no other content."""
        stray = [child.name for child in sorted(directory.iterdir(), key=lambda item: item.name)
                 if child.name != MANIFEST_FILENAME and child.name not in IGNORED_NAMES]
        if stray:
            raise CatalogError(directory.name, [
                f'{name}: a file inside an entry directory that is not {MANIFEST_FILENAME}; this '
                'format references modules and components outside the entry, so nothing belongs here '
                '(a file a reader skipped is content they think is shipped)' for name in stray])
        path = directory / MANIFEST_FILENAME
        if path.is_symlink():
            raise CatalogError(directory.name, [f'{MANIFEST_FILENAME}: a symlink is not followed'])
        if not path.is_file():
            raise CatalogError(directory.name, [f'{MANIFEST_FILENAME}: missing manifest in entry '
                                                f'directory {str(directory)!r}'])
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise CatalogError(directory.name, [f'{MANIFEST_FILENAME}: could not be read '
                                                f'({type(exc).__name__})']) from exc
        if len(raw) > MAX_MANIFEST_BYTES:
            raise CatalogError(directory.name, [f'{MANIFEST_FILENAME}: {len(raw)} bytes exceeds the '
                                                f'{MAX_MANIFEST_BYTES}-byte manifest bound'])
        try:
            text = raw.decode('utf-8')
        except UnicodeError as exc:
            raise CatalogError(directory.name, [f'{MANIFEST_FILENAME}: is not UTF-8 text']) from exc
        return self._parse_manifest(text)

    @staticmethod
    def _parse_manifest(text: str) -> dict[str, Any]:
        """Parse manifest JSON the way this repository parses every hand-written document it trusts.

        A duplicate key refuses rather than letting the later one silently win, and ``NaN``/``Infinity``
        refuse rather than arriving as non-finite floats — the discipline of
        ``platform/verification_policy.py`` and ``anomaly_cursor.py`` applied to a manifest.
        """
        def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            keys = [key for key, _ in pairs]
            if len(set(keys)) != len(keys):
                raise _Rejected()
            return dict(pairs)

        def _constant(_name: str) -> Any:
            raise _Rejected()

        try:
            document = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
        except (_Rejected, json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise CatalogError(MANIFEST_FILENAME, [
                f'{MANIFEST_FILENAME}: parse error ({type(exc).__name__}: {str(exc)[:160]}); a '
                'duplicate key or a non-finite number is refused rather than resolved by precedence']) from exc
        if not isinstance(document, dict):
            raise CatalogError(MANIFEST_FILENAME, [f'{MANIFEST_FILENAME}: did not parse to an object'])
        return document

    # -- resolution against the checkout and the module directory ----------

    def _confined(self, reference: Any, prefix: str) -> tuple[Path | None, str | None]:
        """Return ``(resolved_path, problem)`` for one manifest reference: inside the checkout, or refused.

        Every filesystem question this module asks about a path an entry named is asked through here,
        and the answer is a *resolved* path or a refusal — never an unread-but-inspected file. Two
        checks, in this order, because the cheap one needs no filesystem at all:

        * :func:`entry_manifest.lexical_reference` on the whole reference, which refuses an absolute
          path, a drive/UNC/device form, a backslash separator, an empty, trailing or repeated
          separator, any all-dots segment (``.``, ``..``, ``...``), a segment ending in a dot and any
          control character — so a ``docs/../../../etc/passwd`` never becomes a joined path; and
        * containment of the **resolved** path inside the configured ``repo_root``, which is the half no
          lexical check reaches: a ``components/control`` symlink or NTFS junction can resolve somewhere
          else while every segment stays well-formed. Lexically unchanged mounts are not detected.

        A refusal names the reference (bounded by :func:`_echo`) and the configured root, and never the
        outside location it resolved to, the outside file or anything inside it: the point of refusing
        is that this reader was never given that file. The path handed back is the resolved one, so a
        later ``is_file``/``read_bytes`` walks a chain with no link left in it.

        **The limit, stated rather than promised:** this is a check-then-use sequence. Nothing here
        holds an opened directory handle across the read, so a link swapped in after this answer is a
        TOCTOU gap the same way ``platform/anomaly_cursor.py`` documents its own ancestry check, and a
        filesystem this process cannot see through (a redirected drive letter, a bind mount above the
        root) resolves *as* the root rather than out of it. What is proved is that no read happens
        through a reference this module could see out.
        """
        problem = entry_manifest.lexical_reference(reference)
        if problem is not None:
            return None, (f'{prefix}: {_echo(reference)} is refused as a reference — {problem}; nothing '
                          'in the checkout was opened to find out what it would have reached')
        root = self.repo
        root_real = resolve_reference(root)
        if root_real is None:
            return None, (f'{prefix}: the checkout {str(root)!r} could not be resolved (a symlink loop, '
                          'or a path the platform will not name), so nothing named inside it could be '
                          'checked; nothing was opened')
        resolved = resolve_reference(root / reference)
        if resolved is None:
            return None, (f'{prefix}: {_echo(reference)} could not be resolved inside {str(root)!r} '
                          '(a symlink loop, or a path the platform will not name); nothing was opened')
        if not _is_inside(resolved, root_real):
            return None, (f'{prefix}: {_echo(reference)} resolves outside the checkout {str(root)!r}; a '
                          'parent that resolves out of the tree is refused, and '
                          'the file it would have reached was never opened')
        return resolved, None

    def _check_components(self, manifest: dict[str, Any]) -> list[str]:
        """Prove every component path, pin pointer and evidence path, naming each defect."""
        problems: list[str] = []
        repo = self.repo
        for position, item in enumerate(manifest.get('components') or ()):
            if not isinstance(item, dict):
                continue                                     # :mod:`.manifest` already refused it
            prefix = f'components[{position}]'
            directory, path_problem = self._confined(item['path'], f'{prefix}.path')
            if path_problem is not None:
                problems.append(path_problem)
            elif (repo / item['path']).is_symlink():
                problems.append(f'{prefix}.path: {item["path"]} is a symlink; a registry does not '
                                'follow one out of the component tree it is reading')
            elif not directory.is_dir():
                problems.append(f'{prefix}.path: {item["path"]} is not a directory in {str(repo)!r}; '
                                'an entry may only reference a component that exists')
            else:
                # The status file is read only under a directory this method has already confined and
                # proven real, which is what keeps the ownership rule (an entry may under-claim and
                # never over-claim) from becoming a read of somebody else's tree.
                ceiling, state_problem = self._component_state(directory)
                if state_problem:
                    problems.append(f'{prefix}.state: {item["path"]} — {state_problem}')
                elif ceiling is not None and _STATE_ORDER.index(item['state']) > _STATE_ORDER.index(ceiling):
                    problems.append(f'{prefix}.state: {item["state"]} exceeds what {item["path"]} claims '
                                    f'about itself ({ceiling}, in its own versions.json); an entry may '
                                    'under-claim and never over-claim, because the component file named is '
                                    'the one authority for its status')
            evidence = item.get('conformance_evidence')
            if evidence:
                target, evidence_problem = self._confined(evidence, f'{prefix}.conformance_evidence')
                if evidence_problem is not None:
                    problems.append(evidence_problem)
                elif not target.is_file():
                    problems.append(f'{prefix}.conformance_evidence: {evidence} is not a file in '
                                    f'{str(repo)!r}; a validated claim that cannot name its evidence '
                                    'is refused, not downgraded')
            if item.get('pin'):
                problems.extend(self._check_pin(item['pin'], prefix, item['path']))
        return problems

    def _component_state(self, directory: Path) -> tuple[str | None, str | None]:
        """Return ``(state, problem)`` for what the referenced component claims about itself.

        ``components/<plane>/<name>/versions.json``'s ``status`` key is that claim, and it is the one
        place it is written: `docs/COMPONENTS.md` §2 reads a status from evidence, so a catalogue entry
        that raises it is asserting evidence the component's own file does not hold. **An entry may
        under-claim and never over-claim.** A component with no pin file, or with one that says nothing
        about status, yields ``(None, None)`` — it states no ceiling, and the entry's claim then rests
        on the evidence rule alone. An unreadable file is the same answer here rather than a refusal:
        the entry did not write it, and :meth:`_check_pin` names an unreadable file when a pin actually
        points into it.

        *directory* is the resolved component directory from :meth:`_confined`, so the one file read
        here is inside the configured checkout: a status word from outside the tree is never echoed
        back as this entry's over-claim.
        """
        target = directory / 'versions.json'
        if target.is_symlink() or not target.is_file():
            return None, None
        try:
            raw = target.read_bytes()
            if len(raw) > MAX_PIN_FILE_BYTES:
                return None, None
            document = json.loads(raw.decode('utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
            return None, None
        if not isinstance(document, dict) or 'status' not in document:
            return None, None
        status = document['status']
        if status not in entry_manifest.STATES:
            return None, (f'its versions.json states {status!r} as a status, which is not a word in '
                          'docs/COMPONENTS.md section 2; the catalogue cannot check a claim written in '
                          'a vocabulary the component invented')
        return status, None

    def _check_pin(self, pin: dict[str, Any], prefix: str, component_path: str) -> list[str]:
        """Resolve one pin pointer, and refuse rather than resolve to something vague."""
        problems: list[str] = []
        target, file_problem = self._confined(pin['file'], f'{prefix}.pin.file')
        if file_problem is not None:
            return [file_problem]
        if (self.repo / pin['file']).is_symlink():
            return [f'{prefix}.pin.file: {pin["file"]} is a symlink and is not followed']
        if not target.is_file():
            return [f'{prefix}.pin.file: {pin["file"]} is not a file in {str(self.repo)!r}; a pin has '
                    'exactly one owning file and it is not here']
        try:
            raw = target.read_bytes()
        except OSError as exc:
            return [f'{prefix}.pin.file: {pin["file"]} could not be read ({type(exc).__name__})']
        if len(raw) > MAX_PIN_FILE_BYTES:
            return [f'{prefix}.pin.file: {pin["file"]} is {len(raw)} bytes, over the '
                    f'{MAX_PIN_FILE_BYTES}-byte bound this reader will open']
        try:
            document = json.loads(raw.decode('utf-8'))
        except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
            return [f'{prefix}.pin.file: {pin["file"]} could not be read as JSON '
                    f'({type(exc).__name__})']
        current: Any = document
        for segment in pin['key'].split('.'):
            if not isinstance(current, dict) or segment not in current:
                # The file is inside the checkout by :meth:`_confined`, so naming the keys it holds is a
                # diagnostic about the file the entry pointed at and not a read of something outside.
                available = sorted(current) if isinstance(current, dict) else []
                return [f'{prefix}.pin.key: {pin["key"]} does not resolve in {pin["file"]} '
                        f'(stopped at {segment!r}; available keys here: {available[:10]}); the pin '
                        f'component {component_path!r} owns lives in that file alone']
            current = current[segment]
        if not isinstance(current, str) or not current.strip():
            return [f'{prefix}.pin.key: {pin["key"]} resolves to '
                    f'{type(current).__name__}, not to a pinned value; a pointer must name the string '
                    'that owns the version']
        return problems

    def _available_modules(self) -> dict[str, int]:
        """Map module name -> ``module_version`` for the named module directory, loaded once.

        Raises:
            CatalogError: No module directory was named (a reference nobody can resolve), the
                directory cannot be read, or a module in it is invalid. All three are refusals: this
                registry does not carry an unresolved reference forward as a state.
        """
        if self._module_versions is not None:
            return self._module_versions
        if self.modules is None:
            raise CatalogError(str(self.root), [
                'modules: an entry references a module and this registry names no module directory to '
                'resolve it against; refusing is the only honest answer, because a reference nobody '
                'can check is a promise nobody made'])
        try:
            loaded = ModuleLoader(self.modules, parser=self.module_parser).load()
        except ModuleLoadError as exc:
            raise CatalogError(str(self.root), [
                f'modules: the module directory {str(self.modules)!r} could not be loaded '
                f'({exc.errors[0]})']) from exc
        self._module_versions = {str(module['name']): int(module['module_version'])
                                 for module in loaded}
        return self._module_versions

    def _check_modules(self, manifest: dict[str, Any]) -> list[str]:
        """Resolve each module reference through module contract's own loader."""
        references = manifest.get('modules') or ()
        if not references:
            return []
        try:
            available = self._available_modules()
        except CatalogError as exc:
            return list(exc.errors)
        problems: list[str] = []
        for position, item in enumerate(references):
            if not isinstance(item, dict) or not isinstance(item.get('name'), str):
                continue                                     # :mod:`.manifest` already refused it
            prefix = f'modules[{position}]'
            name = item['name']
            if name not in available:
                problems.append(f'{prefix}.name: no module named {name!r} in '
                                f'{str(self.modules)!r}; available modules: '
                                f'{sorted(available)[:20]}; a catalogue entry may only reference a '
                                'block that exists')
                continue
            minimum = item.get('min_module_version', 1)
            if available[name] < minimum:
                problems.append(f'{prefix}.min_module_version: {name} is at module_version '
                                f'{available[name]}, below the {minimum} this entry was written '
                                'against; a module file changed its own revision and this entry has '
                                'not been re-read against it')
        return problems

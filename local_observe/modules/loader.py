"""Load a directory of module declarations: all-or-nothing, selected, and honest about coverage.

Two v0.1 disciplines are kept verbatim (``legacy:modules/loader.py``), because they are the reason a
malformed module is a compile error and not an incident:

* **The parser import degrades visibly.** :func:`parse_yaml` imports PyYAML inside itself and turns a
  missing one into a ``ModuleLoadError`` that names the dependency and the fix. Unlike v0.1, this
  package does not pretend PyYAML is optional: it is a **base** dependency here
  (``pyproject.toml``), so what the lazy import really buys is the refusal message and an injectable
  parser (a test can pass ``json.loads`` and never touch YAML, and
  ``tests/test_modules_loader.py`` hides ``yaml`` to prove the message itself). What this package does
  guarantee is v0.1's actual floor: it imports no *optional* extra — nothing here needs datasette,
  uvicorn or mcp, which is the claim ``tests/test_optional_dependencies.py`` makes for the CLIs.
* **``load()`` validates every file before retaining any.** Every list below is built in a local and
  assigned to ``self`` on the last line, so a loader that raised holds no modules, no coverage
  verdicts and no assignments. A half-loaded module directory is how a fleet ends up running a module
  nobody reviewed.

What this repository adds on top is the two proofs, and each has a refusal and an honest non-refusal.

* **does this bind?** — refused when a term names no declared resource (``select.resolve``), or when the
  index it was pointed at cannot be opened at all. Reported rather than refused only when no index was
  named: ``selection: 'unchecked'``, which is a stated gap and never a pass.
* **do these series exist?** — refused when a referenced datapoint is a name the store cannot even be
  asked about (``StoreRefused``: outside its selector shape), or when the store answered and showed a
  referenced series with no rows. Reported rather than refused when the store did not answer at all
  (transport down, refused, malformed): ``series: 'unverified'`` — or ``'unchecked'`` when no store was
  named.

The line "referenced" draws is deliberate and it is the one place this brief reads its own task
narrowly. A graph or an alert is a promise to a *human* — a panel that will render, a page that will
fire — so its series must be provable or the module is refused. A declared datapoint no graph and no
alert names is intent ("this collector fragment will produce it"), and refusing it would make a new
module impossible to enable on an installation that has not collected it yet: the module is what turns
collection on downstream, so a store-side proof of a brand-new series is always empty. Those names are
reported as ``intent`` and never as proof. ``docs/COMPONENTS.md``'s "declared dependencies are
satisfied" (§4) is about the first kind, not the second.

An operator sees all of it without opening this file: every non-``proven``/``resolved`` verdict logs one
WARNING through ``local_observe.log``, ``ModuleLoader.coverage`` carries the per-module verdict as a
structured record, and ``ModuleLoader.summary()`` is the JSON-safe form a portal or a conformance
report can carry. Nothing here writes anything, and there is no CLI for it in this wave
(``platform/cli.py`` is not this brief's file).
"""
from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Callable
from typing import Any

from local_observe.log import get_logger
from local_observe.store.client import StoreClient, StoreRefused, Window

from . import schema, select

log = get_logger(__name__)

#: One module file's ceiling. ``conditions.MAX_CONFIG_BYTES`` is 256 KiB for a whole file of 16
#: rules; one declaration of one collection concern needs a quarter of that, and a file bigger than
#: this is several modules pretending to be one.
MAX_MODULE_BYTES = 65_536
#: The store question that answers "does this series exist in the window?" — store facade's own probe kind.
SERIES_PROBE = 'describe-metrics'
#: Extensions the loader reads, and the ones it ignores *by name*. Everything else in the directory is
#: a refusal: v0.1 skipped any non-``.yaml`` file silently, so a ``module.yml`` sat unread in a
#: directory that looked like it had two modules.
LOAD_SUFFIXES = ('.yaml',)
IGNORED_NAMES = ('README.md', 'CONTRACT.md')
#: The verdict words, spelled once. ``selection`` and ``series`` each answer one question and never
#  the other, so a reader cannot mistake "no index named" for "matched nothing".
SELECTION_VERDICTS = ('resolved', 'unchecked')
SERIES_VERDICTS = ('proven', 'unverified', 'unchecked')


class ModuleLoadError(Exception):
    """A module file this loader will not retain.

    Carries the offending path and every defect as one string each (the v0.1 error style), so the
    operator fixes the file in one pass. A raise carries no partial state: see the module docstring.
    """

    def __init__(self, path: str | os.PathLike[str], errors: list[str]) -> None:
        self.path = str(path)
        self.errors = list(errors)
        super().__init__(f"module file '{self.path}' is invalid: " + '; '.join(self.errors))


def parse_yaml(text: str) -> dict[str, Any]:
    """Parse one module file with the inventory's own YAML discipline.

    ``inventory.validation.UniqueLoader`` is reused rather than ``yaml.safe_load`` so a module file is
    held to the same rules as a declaration: duplicate keys refuse instead of silently winning,
    anchors and aliases refuse because a value that appears twice in a document is one value to read
    and two to review, and a bare date stays a string.

    Raises:
        ModuleLoadError: PyYAML is missing (the message names it and how to get it, and never claims a
            ``modules`` extra exists), the text is not valid YAML, or it did not parse to a mapping.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ModuleLoadError('<parser>', [
            'module loading requires pyyaml, a base dependency of this package (pyproject.toml); '
            'install it or run from an environment built from requirements-test-base.txt '
            f'({type(exc).__name__})']) from exc
    from local_observe.inventory import validation       # needs PyYAML itself, hence the order above

    try:
        document = yaml.load(text, Loader=validation.UniqueLoader)
    except (validation.InvalidInventory, yaml.YAMLError) as exc:
        raise ModuleLoadError('<parser>', [f'parse error: {type(exc).__name__}: {exc}']) from exc
    if not isinstance(document, dict):
        raise ModuleLoadError('<parser>', ['module file did not parse to a mapping'])
    return document


@dataclass(frozen=True)
class ModuleCoverage:
    """What one loaded module can actually prove, as opposed to what it claims.

    ``selection`` answers "did this bind to declared resources" and ``series`` answers "does the store
    hold the series this module promises a surface for"; they are separate fields because they are
    separate questions with separate reasons, and collapsing them is how a module that bound to nothing
    comes to look like a module with no data.

    The three name lists partition what the module declared: ``proven`` and ``unverified`` split the
    *referenced* datapoints (a graph or alert names them) and always cover that set, whichever verdict
    is in force — so ``unverified`` holds "the store did not answer" under ``series: 'unverified'`` and
    "nothing was asked" under ``'unchecked'``, which is why the verdict field and not the list carries
    the distinction. ``intent`` is everything declared but referenced by nothing.
    """

    module: str
    selection: str
    series: str
    resource_ids: tuple[str, ...]
    proven: tuple[str, ...]
    intent: tuple[str, ...]
    unverified: tuple[str, ...]
    detail: str

    def __post_init__(self) -> None:
        """Refuse a verdict word this package does not define.

        The two fields answer different questions, so a typo that puts ``'absent'`` in ``series`` (a
        word this loader deliberately never uses — an answered absence is a raise, not a state) would
        otherwise reach a portal as a claim nobody can check. The message names the field, never the
        datapoints, because the datapoints are the payload of a module file.
        """
        if self.selection not in SELECTION_VERDICTS:
            raise ValueError(f'unknown selection verdict: {self.selection!r}')
        if self.series not in SERIES_VERDICTS:
            raise ValueError(f'unknown series verdict: {self.series!r}')

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-safe verdict a portal or an evidence bundle can carry."""
        return {'module': self.module, 'selection': self.selection, 'series': self.series,
                'resource_ids': list(self.resource_ids), 'proven': list(self.proven),
                'intent': list(self.intent), 'unverified': list(self.unverified), 'detail': self.detail}


@dataclass(frozen=True)
class Assignment:
    """One module bound to one declared resource: the work unit an overlay renders against.

    Carries the declaration it came from, because "this host collects host metrics" is only checkable
    beside the revision of the inventory that says the host exists. ``module`` is the retained document
    itself and not a copy — read it, do not edit it; :mod:`.compiler` copies what it returns precisely
    so a caller never has to.
    """

    module_name: str
    resource_id: str
    resource_kind: str
    resource_name: str
    declaration_revision: str
    module: dict = field(repr=False)

    def as_dict(self) -> dict[str, Any]:
        """Return the assignment without the module body, which is the caller's to fetch."""
        return {'module': self.module_name, 'resource_id': self.resource_id,
                'kind': self.resource_kind, 'name': self.resource_name,
                'declaration_revision': self.declaration_revision}


@dataclass
class ModuleLoader:
    """Loads every ``*.yaml`` under *directory*, in sorted order, all-or-nothing.

    Args:
        directory: The operator's module directory. One subdirectory or one unrecognised extension in
            it is a refusal, not a skip.
        parser: Any ``str -> dict``; injectable so the schema and the refusal set run without PyYAML.
        index_path: A built inventory index to resolve ``applies_to`` against. Omit it and every
            module loads with ``selection: 'unchecked'`` and no assignments — a stated gap, never a
            silent pass.
        store: store facade's facade, used only through ``describe``. Omit it and every module loads with
            ``series: 'unchecked'``.
        window: The half-open interval ``describe`` asks over. Required with *store*: a series is a
            claim about a window, and "does it exist" has no answer without one.

    Raises:
        ModuleLoadError: From :meth:`load`, naming the file and every defect.
    """

    directory: Path | str
    parser: Callable[[str], dict[str, Any]] = parse_yaml
    index_path: Path | str | None = None
    store: StoreClient | None = None
    window: Window | None = None
    _modules: list[dict[str, Any]] = field(default_factory=list, init=False, repr=False)
    _coverage: tuple[ModuleCoverage, ...] = field(default=(), init=False, repr=False)
    _assignments: tuple[Assignment, ...] = field(default=(), init=False, repr=False)

    def load(self) -> list[dict[str, Any]]:
        """Parse, validate, select and prove every file; retain nothing unless all of it passed.

        Returns the validated module documents in file order. A malformed, unselectable or
        series-fabricating file raises :class:`ModuleLoadError` and leaves this loader holding the
        empty state it started with — the no-partial-bind rule, which is the whole reason the
        validation pass exists.
        """
        store, window = self._arguments()
        loaded: list[dict[str, Any]] = []
        coverages: list[ModuleCoverage] = []
        assignments: list[Assignment] = []
        seen: dict[str, str] = {}
        for path in self._directory():
            module = self._read(path)
            name = module.get('name')
            if isinstance(name, str) and name in seen:
                raise ModuleLoadError(path, [f'name: duplicate module name {name!r} '
                                             f'(already defined in {seen[name]!r})'])
            if isinstance(name, str):
                seen[name] = str(path)

            matches, selection, revision = self._select(module, path)
            series, proven, unverified, intent, detail, problems = self._prove(
                module, store=store, window=window)
            if problems:
                raise ModuleLoadError(path, problems)
            record = ModuleCoverage(module=name if isinstance(name, str) else '<invalid>',
                                    selection=selection, series=series,
                                    resource_ids=tuple(match[0] for match in matches),
                                    proven=proven, intent=intent, unverified=unverified, detail=detail)
            loaded.append(module)
            coverages.append(record)
            assignments.extend(Assignment(module_name=record.module, resource_id=resource_id,
                                          resource_kind=kind, resource_name=human,
                                          declaration_revision=revision, module=module)
                               for resource_id, kind, human in matches)
            self._report(record)

        # Retained only here: every raise above leaves the loader exactly as empty as it started.
        self._modules = loaded
        self._coverage = tuple(coverages)
        self._assignments = tuple(assignments)
        return copy.deepcopy(self._modules)

    # -- inputs ------------------------------------------------------------

    def _arguments(self) -> tuple[StoreClient | None, Window | None]:
        if (self.store is None) != (self.window is None):
            raise ModuleLoadError(self.directory, [
                'loader: proving series needs both a store and the window to ask about; a store with '
                'no window is an unanswerable question, and a window with no store proves nothing'])
        return self.store, self.window

    def _directory(self) -> list[Path]:
        """Return the module files to read, refusing what it is not willing to read."""
        root = Path(self.directory)
        if not root.is_dir():
            raise ModuleLoadError(root, ['directory: not a directory, so no module could be read'])
        entries = sorted(root.iterdir(), key=lambda item: item.name)
        problems: list[str] = []
        files: list[Path] = []
        for entry in entries:
            if entry.name.startswith('.'):
                continue                                  # editor droppings and dotfiles are not data
            if entry.is_symlink():
                # The one filesystem question asked here, and refused rather than followed: a module
                # directory is operator content, and a link out of it points at a file this loader was
                # not given. Same posture as `anomaly_cursor.symlink_present`, including the reason it is
                # tested by patching the predicate rather than by creating a link on a Windows host.
                problems.append(f'{entry.name}: a symlink is not loaded')
            elif entry.is_dir():
                problems.append(f'{entry.name}: a subdirectory is not loaded; a module tree nobody '
                                'walks is a module that silently does not exist')
            elif entry.suffix in LOAD_SUFFIXES:
                files.append(entry)
            elif entry.name in IGNORED_NAMES:
                continue
            else:
                problems.append(f'{entry.name}: not a .yaml module file and not one of '
                                f'{", ".join(IGNORED_NAMES)}; the loader refuses to skip a file it '
                                'was given')
        if problems:
            raise ModuleLoadError(root, problems)
        return files

    def _read(self, path: Path) -> dict[str, Any]:
        """Read one bounded module file, parse it and validate it against the schema."""
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ModuleLoadError(path, [f'file: could not be read ({type(exc).__name__})']) from exc
        if len(raw) > MAX_MODULE_BYTES:
            raise ModuleLoadError(path, [f'file: {len(raw)} bytes exceeds the {MAX_MODULE_BYTES}-byte '
                                         'module bound'])
        try:
            text = raw.decode('utf-8')
        except UnicodeError as exc:
            raise ModuleLoadError(path, ['file: is not UTF-8 text']) from exc
        try:
            module = self.parser(text)
        except ModuleLoadError as exc:
            raise ModuleLoadError(path, exc.errors) from exc
        except Exception as exc:                        # a custom parser's own failure, named
            raise ModuleLoadError(path, [f'parse error: {type(exc).__name__}: {exc}']) from exc
        result = schema.validate(module)
        if not result.ok:
            raise ModuleLoadError(path, list(result.errors))
        return module

    # -- the two proofs ----------------------------------------------------

    def _select(self, module: dict[str, Any], path: Path) -> tuple[list[tuple[str, str, str]], str, str]:
        """Resolve ``applies_to`` against the named index, or say why nothing was resolved.

        Returns ``(matches, selection_verdict, declaration_revision)`` where a match is a
        ``(resource_id, kind, name)`` triple in term order. With no index named the verdict is
        ``'unchecked'`` and the match list is empty — a stated gap in a record the operator can read,
        which is the only honest shape available to a loader that was given nothing to ask.

        Raises:
            ModuleLoadError: A term the grammar refuses, a term that matches no declared resource, or
                an index that cannot be opened. All three are refusals and none of them is reported as
                "this module applies to nothing".
        """
        if self.index_path is None:
            return [], 'unchecked', ''
        try:
            selection = select.resolve(select.parse(module['applies_to']), self.index_path)
        except select.SelectorRefusal as exc:
            raise ModuleLoadError(path, [f'applies_to: {exc}']) from exc
        return ([(match.resource_id, match.kind, match.name) for match in selection.matches],
                'resolved', selection.revision.get('declaration_revision', ''))

    def _prove(self, module: dict[str, Any], *, store: StoreClient | None,
               window: Window | None) -> tuple[str, tuple[str, ...], tuple[str, ...],
                                              tuple[str, ...], str, list[str]]:
        """Ask the store whether each *referenced* series exists, and report the verdict.

        Returns ``(series_verdict, proven, unverified, intent, detail, problems)``. ``problems`` is
        non-empty only when the store answered and said *no*, or when the name could not be asked at
        all: both mean the module promises a panel or a page over a series nobody has. A store that
        never answers is ``'unverified'`` and the module still loads — the rule
        ``detections.evaluate`` applies to a stale sample, where blindness is reported and never
        dressed up as either a pass or an absence.

        One failed request marks every referenced series of this module unverified and stops asking:
        a store that is down does not need one timeout per series to say it is down, and a verdict
        assembled from a partly-answered list would read as a list of absences.
        """
        declared = schema.datapoint_names(module)
        referenced = schema.referenced_datapoints(module)
        intent = tuple(name for name in declared if name not in set(referenced))
        if store is None or window is None:
            return ('unchecked', (), referenced, intent,
                    'no store was named, so no series was asked about; these datapoints are declared '
                    'intent, not proven coverage', [])
        proven: list[str] = []
        absent: list[str] = []
        for name in referenced:
            try:
                presence = store.describe(SERIES_PROBE, window=window, selectors={'metric_name': name})
            except StoreRefused as exc:
                # The facade refused to ask, so this is a defect in the document, not a store outage.
                return ('unverified', tuple(proven), referenced, intent,
                        f'the store refused the question about {name}: {str(exc)[:160]}',
                        [f'datapoints: {name} cannot be asked of the store as a metric name ({exc}); '
                         'a series name this query adapter cannot bind is not a provable datapoint'])
            except Exception as exc:                    # the store did not answer, in its own words
                return ('unverified', (), referenced, intent,
                        f'the store did not answer ({type(exc).__name__}); every referenced series of '
                        f'this module is unverified, not absent', [])
            if presence.row_count > 0:
                proven.append(name)
            else:
                absent.append(name)
        problems = [f'default_graphs/default_alerts: {name} names a series the store holds no rows for '
                    f'in [{window.start}, {window.end}); a panel or a page over it would be fabricated '
                    f'coverage' for name in absent]
        return ('proven', tuple(proven), (), intent,
                'the store answered for every referenced datapoint', problems)

    # -- what the operator sees -------------------------------------------

    def _report(self, coverage: ModuleCoverage) -> None:
        """One WARNING per module whose proof is not complete, and nothing else.

        Loudness is the whole point of the verdict: an operator who never reads ``coverage`` still sees
        the line in the worker's log, and a module that loaded ``unverified`` is not a module that
        passed. The key is ``module_name`` because ``module`` is a reserved ``LogRecord`` attribute and
        ``logging`` raises a KeyError for the collision rather than dropping the field.
        """
        if coverage.selection == 'resolved' and coverage.series == 'proven':
            return
        log.warning('Module coverage incomplete', extra={
            'module_name': coverage.module, 'selection': coverage.selection, 'series': coverage.series,
            'resources': len(coverage.resource_ids), 'proven': len(coverage.proven),
            'intent': len(coverage.intent), 'unverified': list(coverage.unverified)[:20],
            'detail': coverage.detail})

    @property
    def modules(self) -> list[dict[str, Any]]:
        """The validated module documents, deep-copied.

        A caller may add, remove or rewrite what it is handed without touching what the loader judged,
        so a renderer cannot turn one render into a different second render. The compiler copies again
        on its way out for the same reason.
        """
        return copy.deepcopy(self._modules)

    @property
    def coverage(self) -> tuple[ModuleCoverage, ...]:
        """One :class:`ModuleCoverage` per loaded module, in the same order as :attr:`modules`."""
        return self._coverage

    def assignments(self) -> tuple[Assignment, ...]:
        """Every (module, declared resource) pair, or empty when no index was named.

        Empty means either "nothing was resolved" or "the directory holds no modules", and
        :attr:`coverage` names which: its ``selection`` field is ``unchecked`` in the first case and
        the tuple is empty in the second.
        """
        return self._assignments

    def summary(self) -> dict[str, Any]:
        """Return the load's whole verdict as one JSON-safe record, for a report or a conformance run."""
        return {'directory': str(self.directory), 'modules': [module.get('name') for module in self._modules],
                'assignments': [assignment.as_dict() for assignment in self._assignments],
                'coverage': [record.as_dict() for record in self._coverage],
                'selection': sorted({record.selection for record in self._coverage}),
                'series': sorted({record.series for record in self._coverage})}




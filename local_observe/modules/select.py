"""The module selector: identity terms resolved against a built inventory index (module contract).

A module says who it applies to in ``applies_to``. v0.1 spelled that as one free-text rule string in
its own ``key=value AND ...`` grammar (``legacy:modules/schema.py:1-13``), parsed by a small engine and
matched against name-derived resources. That grammar cannot cross into this repository: identity here
is a UUID minted at declaration with hostname and ``host.id`` as indexed aliases (docs/DECISIONS.md
canonical identifier, docs/CONTRACTS.md §3), and v0.1's ``key`` space was its whole ``Resource`` object — free-form
attributes, a decommission flag, a derived name. A selector that accepted those words would select
things this repository does not have.

So the selector is a **structured term list, not a string**. That is the contract change this brief
owes a reviewer's eyes. The grammar as it landed:

.. code-block:: yaml

    applies_to:
      any_of:                          # the only key; 1..100 terms, OR'd together
        - id: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1
        - alias: {type: host.id, value: synthetic-host-001}
        - alias: {type: hostname, value: probe-1.example.test}

* A term is exactly one of ``id`` (a canonical lowercase UUID — the shape
  ``inventory/schemas/common.json#/$defs/uuid`` admits) or ``alias`` (``type`` from that file's alias
  vocabulary, ``value``, optional ``scope``).
* Every term resolves through ``inventory/index.py``'s own ``resolve()`` against the **indexed**
  alias table, normalised by ``validation.alias_key`` — so ``Probe-1.Example.Test.`` and
  ``probe-1.example.test`` are the same term here exactly as they are the same row in the index, and two
  spellings of one target are a refusal rather than two bindings.
* ``any_of`` is a disjunction because each term names at most one resource: a conjunction of identity
  terms is either one resource or nothing, and v0.1's ``AND`` was only ever useful over the attribute
  keys this schema does not expose.
* Nothing else is selectable. Not ``kind``, not an attribute, not a name. Fleet-wide selection is the
  operator enumerating the resources he already declared, which is what his inventory file is; a
  ``kind=`` term would be a selector whose match set moves when somebody else edits a declaration,
  and a module's promise about *these* series must not move under it. module catalog (the catalogue) is the
  card to revisit this with a consumer in front of it, not in advance of one.

Two refusals carry the honesty. A term that matches nothing is a refusal: a module that half-binds is
the partial-bind defect in a new costume, and a module binding to nothing fabricates coverage for
resources nobody declared. And a term outside this grammar is refused with the v0.1 form named, so an
operator copying an old module learns the new grammar at load rather than from a silently empty
binding.

The selection answer carries the **declaration provenance** (revision and sha256 of the index it was
resolved against, read through ``topology.Topology.revision()``, the only published reader of
``build_metadata``): "this module binds to these three resources" is only checkable when it also says
which declaration said so.
"""
from __future__ import annotations

import re
import sqlite3
import uuid as uuid_module
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from local_observe import topology
from local_observe.inventory import index
from local_observe.inventory.validation import InvalidInventory, alias_key

#: Terms one selector may name. A module binding more resources than this is a fleet declaration, not
#: a module, and the bound exists so the resolve loop's query count is knowable at review time.
MAX_TERMS = 100
#: Same ceiling as ``inventory/schemas/common.json#/$defs/text`` (``maxLength`` 256): a selector value
#: is an alias value, and the index will not have stored one longer than that.
MAX_VALUE_CHARS = 256
#: The UUID shape, restated from ``common.json#/$defs/uuid`` (that file is not this brief's to edit,
#: so the pattern is pinned against it by ``tests/test_modules_select.py``).
UUID_SHAPE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
#: The alias types the index actually keys on, restated from ``common.json#/$defs/alias.type`` and
#: pinned against that file by the same test.
ALIAS_TYPES = ('host.id', 'hostname', 'ip', 'legacy_id', 'service.name')

TERM_KEYS = frozenset({'id', 'alias'})
ALIAS_KEYS = frozenset({'type', 'value', 'scope'})
SELECTOR_KEYS = frozenset({'any_of'})


class SelectorRefusal(InvalidInventory):
    """A selector this module will not resolve. It is an ``InvalidInventory``, so an HTTP edge that
    already classifies inventory refusals as a chosen 400 classifies these the same way (the
    ``topology.TopologyRefusal`` precedent)."""


@dataclass(frozen=True)
class Term:
    """One identity term: either a declared UUID or one indexed alias."""

    resource_id: str | None = None
    alias: dict[str, str] | None = None

    @property
    def kind(self) -> str:
        """``'id'`` or ``'alias'`` — the two things a term can be."""
        return 'id' if self.resource_id is not None else 'alias'

    def key(self) -> tuple[str, str, str, str]:
        """The dedup key: two spellings that reach one target compare equal here."""
        if self.alias is not None:
            return ('alias', self.alias['scope'], self.alias['type'], self.alias['value'])
        return ('id', '', '', self.resource_id or '')

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-safe form a portal or an evidence bundle can carry."""
        return {'id': self.resource_id} if self.alias is None else {'alias': dict(self.alias)}


@dataclass(frozen=True)
class Selector:
    """A parsed ``applies_to``: an ordered, duplicate-free disjunction of :class:`Term`."""

    terms: tuple[Term, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the selector in the document shape it was parsed from."""
        return {'any_of': [term.as_dict() for term in self.terms]}


@dataclass(frozen=True)
class Match:
    """One term and the declared resource it resolved to, with the two words a human reads."""

    term: int
    resource_id: str
    kind: str
    name: str

    def as_dict(self) -> dict[str, Any]:
        return {'term': self.term, 'resource_id': self.resource_id, 'kind': self.kind,
                'name': self.name}


@dataclass(frozen=True)
class Selection:
    """What a selector resolved to, and the declaration that made it true."""

    resource_ids: tuple[str, ...]
    matches: tuple[Match, ...]
    revision: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {'resource_ids': list(self.resource_ids), 'matches': [m.as_dict() for m in self.matches],
                'declaration_revision': self.revision.get('declaration_revision', ''),
                'declaration_sha256': self.revision.get('declaration_sha256', '')}


def selector_errors(document: Any, *, prefix: str = 'applies_to') -> tuple[list[str], Selector | None]:
    """Check one ``applies_to`` value without raising; return ``(errors, selector)``.

    One error string per defect, each naming the offending field path (the v0.1 loader's discipline,
    which is what lets the module loader refuse a file with a precise list instead of one guess). The
    selector is returned only when the document is fully valid, so no caller can act on a half-read
    selector.

    Refusal sentences name a **term position and a field**, never the term's own value: these strings
    can reach an HTTP error body the way ``api.py`` builds one, and a hostname is not something to
    echo back to an anonymous reader.
    """
    errors: list[str] = []
    if isinstance(document, str):
        rule = ' (the v0.1 `key=value AND ...` form)' if ('=' in document or ' AND ' in document) else ''
        return ([f'{prefix}: a rule string is not this grammar{rule}; write '
                 f'{prefix}: {{any_of: [{{id: <declared uuid>}}]}} or '
                 '{any_of: [{alias: {type: hostname, value: <name>}}]}'], None)
    if not isinstance(document, Mapping):
        return ([f'{prefix}: must be a mapping holding only `any_of`'], None)
    for key in sorted(set(document) - SELECTOR_KEYS):
        errors.append(f'{prefix}.{key}: unknown field (this grammar selects by declared identity only)')
    if 'any_of' not in document:
        errors.append(f'{prefix}.any_of: missing required field')
        return (errors, None)
    items = document['any_of']
    if not isinstance(items, list) or not items:
        errors.append(f'{prefix}.any_of: must be a non-empty list of identity terms')
        return (errors, None)
    if len(items) > MAX_TERMS:
        errors.append(f'{prefix}.any_of: at most {MAX_TERMS} terms are allowed, found {len(items)}')
        return (errors, None)

    terms: list[Term] = []
    seen: dict[tuple[str, str, str, str], int] = {}
    for position, item in enumerate(items):
        where = f'{prefix}.any_of[{position}]'
        if not isinstance(item, Mapping):
            errors.append(f'{where}: must be a mapping holding exactly one of `id` or `alias`')
            continue
        for key in sorted(set(item) - TERM_KEYS):
            errors.append(f'{where}.{key}: unknown field')
        present = TERM_KEYS & set(item)
        if len(present) != 1:
            errors.append(f'{where}: exactly one of `id` or `alias` is required, found {len(present)}')
            continue
        term, problem = _build_term(item)
        if problem is not None:
            errors.append(f'{where}.{problem[0]}: {problem[1]}')
            continue
        if term is None:      # defensive: _build_term never returns (None, None)
            errors.append(f'{where}: could not be read as an identity term')
            continue
        if term.key() in seen:
            errors.append(f'{where}: names the same target as {prefix}.any_of[{seen[term.key()]}]')
            continue
        seen[term.key()] = position
        terms.append(term)
    if errors:
        return (errors, None)
    return ([], Selector(tuple(terms)))


def _build_term(item: Mapping[str, Any]) -> tuple[Term | None, tuple[str, str] | None]:
    """Return ``(term, None)`` or ``(None, (field, reason))`` for one validated term mapping."""
    if 'id' in item:
        value = item['id']
        if not isinstance(value, str) or not UUID_SHAPE.fullmatch(value):
            return (None, ('id', 'must be a canonical lowercase UUID (the declared id shape)'))
        try:
            parsed = uuid_module.UUID(value)
        except ValueError as exc:
            return (None, ('id', f'must be a canonical UUID: {type(exc).__name__}'))
        if str(parsed) != value:
            return (None, ('id', 'must be a canonical lowercase UUID'))
        return (Term(resource_id=value), None)

    alias = item['alias']
    if not isinstance(alias, Mapping):
        return (None, ('alias', 'must be a mapping of type/value and optional scope'))
    unknown = sorted(set(alias) - ALIAS_KEYS)
    if unknown:
        return (None, (f'alias.{unknown[0]}', 'unknown field'))
    missing = ALIAS_KEYS - {'scope'} - set(alias)
    if missing:
        return (None, ('alias', 'missing required field(s): ' + ', '.join(sorted(missing))))
    kind, value, scope = alias['type'], alias['value'], alias.get('scope', '')
    if not isinstance(kind, str) or kind not in ALIAS_TYPES:
        return (None, ('alias.type', f'must be one of: {", ".join(ALIAS_TYPES)}'))
    if not isinstance(value, str) or not value or len(value) > MAX_VALUE_CHARS:
        return (None, ('alias.value', f'must be 1..{MAX_VALUE_CHARS} characters'))
    if not isinstance(scope, str) or len(scope) > 128:
        return (None, ('alias.scope', 'must be at most 128 characters'))
    normalized = {'scope': scope, 'type': kind, 'value': value}
    try:
        # The index's own normalisation, reused and not restated: hostname case and trailing dot, and
        # an IP's canonical form, are what the aliases table is keyed on. A selector that skipped this
        # would refuse a term the index actually holds.
        _scope, _type, alias_value = alias_key(normalized)
    except (InvalidInventory, KeyError, TypeError):
        return (None, ('alias.value', 'is not a valid hostname, host id or address once normalised'))
    return (Term(alias={'scope': _scope, 'type': _type, 'value': alias_value}), None)


def parse(document: Any) -> Selector:
    """Return the :class:`Selector` ``document`` spells; raise :class:`SelectorRefusal` if it does not.

    The raising twin of :func:`selector_errors`, for a caller holding one selector rather than a whole
    module file. Every defect is named in the one message.
    """
    errors, selector = selector_errors(document)
    if errors or selector is None:
        raise SelectorRefusal('; '.join(errors) or 'applies_to: nothing to select')
    return selector


def resolve(selector: Selector, index_path: Path | str) -> Selection:
    """Resolve every term against one built inventory index, or refuse naming each dead term.

    Args:
        selector: A parsed :class:`Selector`.
        index_path: The SQLite index ``inventory.index.build`` wrote. It is opened read-only per call
            through ``index.readonly`` (which re-checks the application id and schema version), so a
            rotated index is never half-read.

    Returns:
        The matched resource ids in term order, each with its kind and name, plus the declaration
        revision and sha256 behind them.

    Raises:
        SelectorRefusal: The index cannot be read (missing, foreign, or a newer schema — refused,
            never reported as "matches nothing", because a broken deployment and an empty declaration
            are different facts); or any term names no declared resource; or two terms reach the same
            resource by different keys.
    """
    path = Path(index_path)
    try:
        revision = topology.Topology(path).revision()
        with index.readonly(path) as connection:
            matches: list[Match] = []
            dead: list[str] = []
            for position, term in enumerate(selector.terms):
                found = _one(connection, term)
                if found is None:
                    dead.append(f'applies_to.any_of[{position}] ({term.kind})')
                    continue
                matches.append(Match(position, found['resource_id'], found['kind'], found['name']))
    except (sqlite3.Error, InvalidInventory) as exc:
        raise SelectorRefusal(f'applies_to: the declared inventory index at this path could not be '
                              f'read as an index ({type(exc).__name__}); a selection is never reported '
                              f'as empty because the file was unreadable') from exc
    if dead:
        raise SelectorRefusal('applies_to: term(s) name no declared resource: ' + ', '.join(dead)
                              + '; a module that binds nothing promises coverage nobody declared')
    resource_ids = [match.resource_id for match in matches]
    if len(set(resource_ids)) != len(resource_ids):
        raise SelectorRefusal('applies_to: two terms resolve to one resource; name each target once')
    return Selection(tuple(resource_ids), tuple(matches), revision)


def _one(connection, term: Term) -> dict[str, str] | None:
    """Resolve one term through the index's own ``resolve()``, or return None.

    No SQL is written here beyond the resource lookup the index does not offer typed: ``index.resolve``
    answers identity and status, and the kind/name pair that rides a :class:`Match` (so an operator
    reads "probe-1 (host)" and not a UUID) is the one column read this module owes itself. Widening
    this is a reason to add a typed read to ``inventory/index.py``, which is not this brief's to edit.
    """
    if term.resource_id is not None:
        answer = index.resolve(connection, resource_id=term.resource_id)
    else:
        answer = index.resolve(connection, aliases=[dict(term.alias or {})])
    if answer['status'] != 'resolved' or not answer['resource_id']:
        return None
    row = connection.execute('SELECT id, kind, name FROM resources WHERE id=?',
                             (answer['resource_id'],)).fetchone()
    if row is None:
        return None
    return {'resource_id': row['id'], 'kind': row['kind'], 'name': row['name']}

"""Multi-instance expansion: one datapoint set per discovered instance (module contract).

v0.1's rule, ported (``legacy:modules/compiler.py``): a module carrying the optional ``multi_instance``
block names a *discovery* seam and a label template, and the compiler turns one discovered row into
one datapoint set — the tracked check being "a multi-instance module yields one datapoint set per
discovered instance (e.g. per interface)". Discovery stays an **injected argument**: this module never
talks to a device, opens a socket or runs a scraper, so a test hands it rows and the rows are the whole
input. Every defect is named in one raise and no partial set escapes, which is the loader's all-or-nothing
rule applied to the step after it.

**The shipped example set is empty, deliberately, and this is the choice a reviewer should read
first.** ``examples/modules/`` carries no ``multi_instance`` module, because nothing in this repository
discovers instances yet: the declared inventory is hand-written, the discovery providers emit
*observations about resources*, not sub-resource rows, and the one per-port idea v0.1 had was SNMP,
which this brief rules out. A compiler with no consumer is how the second prototype library arrived
(dead code culled it), so the code ships with its refusal set under test and without a worked example. The
consumer that would justify one is a source whose rows are already named — an SNMP-capable collector
fragment, or a device table an operator's overlay feeds in — and when it lands it lands with a module
file in ``examples/modules/`` and the row shape written here.

Two port deltas from v0.1, both forced by this repository's contracts:

* **Series names are not rewritten.** v0.1 renamed each datapoint to ``<name>.<instance label>``.
  Here a series is ``(metric_name, labels)`` — ``store/client.py`` binds ``metric_name`` as an exact
  match and ``describe-metrics`` proves existence on that pair — so ``system.cpu.time.eth0`` would be
  a name no store can ever show and the module would fabricate the coverage module contract exists to prevent.
  The instance identity therefore rides in :attr:`CompiledSet.labels` (which is what the collector's
  resource/record attributes become), and the metric name stays what the receiver emits.
* **A discovered row may name its resource.** ``resource_id`` is a canonical declared UUID when
  present, and the duplicate-label guard keys on ``(resource_id, label)`` rather than the label alone.
  v0.1's global label check would refuse the same ``eth0`` on two hosts, which is a common real case
  and not a defect.
"""
from __future__ import annotations

import re
import uuid as uuid_module
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import schema

#: Rows one compile call may carry. One datapoint set per instance is a cardinality decision, not a
#: detail — the same arithmetic that makes the collector's own relabel rule keep only named units — so
#: a discovery run above this is refused rather than emitted and discovered downstream as a cost.
MAX_INSTANCES = 256
#: Labels one instance row may carry, and how long each may be. The store's own label bound
#: (``store/client.LABEL``) is 128 characters, so a longer value could never become a series label.
MAX_LABELS = 32
MAX_LABEL_CHARS = 128
#: Characters a rendered instance label may contain. A label reaches a collector config and a store
#: label set, so whitespace and control characters are refused rather than quoted around.
INSTANCE_LABEL_SHAPE = re.compile(r'^[A-Za-z0-9_.:/-]{1,128}$')
#: The scalar types a discovered row's fields may hold. A nested value would be stringified into a
#: Python repr, which is how a dict-shaped scrape row becomes a label nobody can query.
SCALAR_TYPES = (str, int, float, bool)


class ModuleCompileError(Exception):
    """A module could not be compiled against its discovered instances.

    Carries the module name and every defect as one string each (the ``ModuleLoadError`` style), and
    the same contract: a compile that raised returned no datapoint sets.
    """

    def __init__(self, module_name: str, errors: list[str]) -> None:
        self.module_name = module_name
        self.errors = list(errors)
        super().__init__(f"module {module_name!r} failed to compile: " + '; '.join(self.errors))


@dataclass(frozen=True)
class CompiledSet:
    """One compiled datapoint set: what to collect, for one instance of one declared resource.

    A single-instance module yields exactly one of these with ``instance_label`` and ``instance``
    ``None`` and an empty ``labels`` map; a multi-instance module yields one per discovered row.
    ``datapoints`` holds copies — a caller may not mutate the loaded module through a compiled set.
    """

    module_name: str
    resource_id: str | None
    datapoints: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    labels: dict[str, str] = field(default_factory=dict)
    instance_label: str | None = None
    instance: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return the set as JSON-safe text, without the module body."""
        return {'module': self.module_name, 'resource_id': self.resource_id,
                'datapoints': [dict(point) for point in self.datapoints], 'labels': dict(self.labels),
                'instance_label': self.instance_label, 'instance': dict(self.instance or {})}


def compile_module(module: Mapping[str, Any],
                   instances: Sequence[Mapping[str, Any]] | None = None) -> list[CompiledSet]:
    """Expand one validated module into datapoint sets, one per discovered instance.

    Args:
        module: A module document. It is re-validated here, because a compiler that trusts its input
            is how a malformed block reaches a collector config.
        instances: The injected discovered rows. **Required** for a multi-instance module (``[]`` is a
            legitimate "nothing discovered" and returns no sets) and **refused** for a single-instance
            one, so a caller cannot quietly hand rows to a module that declared no seam to run.

    Returns:
        The compiled sets, in row order. Never mutates *module*.

    Raises:
        ModuleCompileError: Every defect at once — an invalid module, a row that is not a mapping, a
            row missing a field the template names, a label that renders blank or outside the label
            shape, a duplicate ``(resource_id, label)`` pair, an undeclared-shaped ``resource_id``, a
            row field that is not a scalar, or a run above :data:`MAX_INSTANCES`.
    """
    result = schema.validate(module)
    name = module.get('name') if isinstance(module, Mapping) else None
    module_name = name if isinstance(name, str) and name else '<invalid>'
    if not result.ok:
        raise ModuleCompileError(module_name, list(result.errors))

    block = module.get('multi_instance')
    if block is None:
        if instances is not None:
            raise ModuleCompileError(module_name, [
                'instances: a discovered-instance list was supplied but the module declares no '
                'multi_instance block, so nothing was asked to discover them'])
        return [CompiledSet(module_name=module_name, resource_id=None,
                            datapoints=tuple(dict(point) for point in module['datapoints']))]

    if instances is None:
        raise ModuleCompileError(module_name, [
            'instances: a multi-instance module needs the discovered rows to compile against (run '
            f'discovery source {block["discovery"]["source"]!r} and pass its rows, or pass [] when '
            'discovery found nothing)'])
    rows = list(instances)
    if len(rows) > MAX_INSTANCES:
        raise ModuleCompileError(module_name, [
            f'instances: {len(rows)} rows exceeds the {MAX_INSTANCES}-instance bound; one datapoint '
            'set per instance is the cardinality this contract promises to name'])

    template = block['instance_label']
    wanted = schema.instance_label_fields(template)
    errors: list[str] = []
    seen: dict[tuple[str, str], int] = {}
    compiled: list[CompiledSet] = []
    for position, row in enumerate(rows):
        prefix = f'instances[{position}]'
        if not isinstance(row, Mapping):
            errors.append(f'{prefix}: must be a mapping of discovered-instance fields')
            continue
        resource_id, problem = _row_resource(row.get('resource_id'))
        if problem:
            errors.append(f'{prefix}.{problem[0]}: {problem[1]}')
            continue
        labels, problem = _row_labels(row)
        if problem:
            errors.append(f'{prefix}.{problem[0]}: {problem[1]}')
            continue
        missing = [name for name in wanted if name not in labels]
        if missing:
            errors.append(f'{prefix}: discovered row carries no {", ".join(missing)} for the '
                          f'instance_label template {template!r}')
            continue
        try:
            label = template.format_map({key: labels[key] for key in wanted})
        except (IndexError, KeyError, ValueError) as exc:
            errors.append(f'{prefix}: instance_label template {template!r} did not render '
                          f'({type(exc).__name__})')
            continue
        if not INSTANCE_LABEL_SHAPE.fullmatch(label):
            errors.append(f'{prefix}: rendered instance label is outside {INSTANCE_LABEL_SHAPE.pattern} '
                          '(no whitespace, no control characters, 1-128 characters)')
            continue
        key = (resource_id or '', label)
        if key in seen:
            errors.append(f'{prefix}: duplicate instance label for the same resource '
                          f'(also produced by instances[{seen[key]}])')
            continue
        seen[key] = position
        labels['instance'] = label        # v0.1's rule, ported: the label is what makes the series distinct
        compiled.append(CompiledSet(module_name=module_name, resource_id=resource_id,
                                    datapoints=tuple(dict(point) for point in module['datapoints']),
                                    labels=labels, instance_label=label, instance=dict(row)))
    if errors:
        raise ModuleCompileError(module_name, errors)      # all-or-nothing, like the loader
    return compiled


def _row_resource(value: Any) -> tuple[str | None, tuple[str, str] | None]:
    """Return ``(resource_id, None)``, ``(None, None)`` when the row names none, else the problem."""
    if value is None:
        return (None, None)
    if not isinstance(value, str):
        return (None, ('resource_id', 'must be a canonical declared UUID string when present'))
    try:
        parsed = uuid_module.UUID(value)
    except ValueError as exc:
        return (None, ('resource_id', f'is not a canonical UUID ({type(exc).__name__})'))
    if str(parsed) != value:
        return (None, ('resource_id', 'must be a canonical lowercase UUID'))
    return (value, None)


def _row_labels(row: Mapping[str, Any]) -> tuple[dict[str, str], tuple[str, str] | None]:
    """Stringify one discovered row into series labels, refusing what cannot be a label.

    The problem comes back as ``(field, reason)`` and the caller prefixes it with the row position, so
    the sentence names a field the way the loader's do.
    """
    if len(row) + 1 > MAX_LABELS:      # +1 for the `instance` label the compiler itself adds
        return ({}, ('fields', f'a discovered row may carry at most {MAX_LABELS - 1} fields beside the '
                               'instance label'))
    if 'instance' in row:
        return ({}, ('instance', 'a discovered row may not name the label the compiler renders'))
    labels: dict[str, str] = {}
    for key, value in row.items():
        if not isinstance(key, str) or not key.isidentifier():
            return ({}, (str(key), 'field names must be plain identifiers'))
        if not isinstance(value, SCALAR_TYPES) or (isinstance(value, float) and value != value):
            return ({}, (key, 'field values must be scalars (a nested value would become a Python '
                              'repr, which is a label nobody can query)'))
        text = str(value)
        if not text or len(text) > MAX_LABEL_CHARS:
            return ({}, (key, f'field values must render to 1..{MAX_LABEL_CHARS} characters'))
        labels[key] = text
    return (labels, None)

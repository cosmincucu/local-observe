"""The monitoring-module contract: what a "block" declares (module contract).

deployment baseline makes this product "blocks, they can pick and choose what to enable", and docs/COMPONENTS.md §3
has sold optional modules (a Portainer integration, the Zeek/Suricata/Falco row, whose own wording
already says "documented per module") with no file in this repository defining what one *is*. That
absence is why the collector question, those two rows and the catalogue idea (module catalog) all stall: there
is nothing to declare with. This module is that schema.

**Why an explicit validator and not another JSON Schema file.** ``local_observe/inventory/schemas/``
is the house pattern for a *document* contract, and it was read first. Two facts decided against
copying it here. (1) Most of this contract is cross-field: a graph may only name a declared datapoint,
an alert may only name a condition mode that exists, a selector must parse. A JSON Schema cannot say
any of that, so a schema file would still need this layer beside it, and two sources for one contract
is the defect ``DEPENDENCIES.md`` exists to keep visible. (2) ``validation.validate_schema`` reports
the *first* error only, which is wrong for a file an operator hand-writes: the loader's whole value is
naming every defect in one refusal, so a fixed module file is one round trip and not six. The newest
contracts in this repository use this shape — ``platform/conditions.RULE_KEYS``,
``platform/escalation.CHAIN_KEYS`` — closed key sets and named refusals. If a machine-readable schema
file is ever wanted for editor completion, generate it from these constants rather than beside them.

The field contract, as it landed in ``schema_version`` 1
------------------------------------------------------------------
Required, in the order a reader meets them:

* ``schema_version`` — the only value is ``1``; this is the upgrade seam, below.
* ``name`` — a bounded lowercase label, unique within one directory (a duplicate is refused, naming the
  file that claimed it first).
* ``module_version`` — an integer >= 1, the operator's own revision counter.
* ``applies_to`` — the selector; :mod:`.select` is its grammar and its refusal set.
* ``collection`` — an OTel fragment: receiver, interval, scraper names, resource-attribute keys. The
  metric *names* of that fragment are ``datapoints[].name`` and deliberately not a second list inside
  ``collection``, which would be one more thing free to drift from the first.
* ``datapoints`` — 1..64 series the module promises, each with ``name``, ``unit`` and ``type``.

Optional: ``description``, ``default_graphs``, ``default_alerts``, ``multi_instance``. No other key is
admitted anywhere in the document, at any depth.

``collection`` is a **shape, not a config**: ``receiver``, ``interval_seconds``, ``scrapers`` and
``resource_attributes`` and nothing else. There is deliberately no free-form ``params`` map (v0.1 had
one): every place an endpoint, a community string or a credential could arrive is a place one
eventually does, and this product's rule is that a credential is a mounted file the operator's overlay
names (``components/data/agent-linux/collector.yaml`` reads its ingest token as ``${file:…}``). A
module names *what* to collect; the operator's overlay says *how from where*, and only his collector
run — ``scripts/check_foundation.py``'s ``check_collector`` and the conformance recipe — can prove a
fragment renders. This repository never writes a collector config.

Three boundaries that belong in this docstring because a reader would otherwise look in the wrong file
----------------------------------------------------------------------------------------------------------------
* **No dashboard generation.** ``default_graphs`` is a *declaration of intent*, consumed by the
  operator's own dashboard repository. Nothing in ``local_observe/deployment/`` renders it
  and nothing here asks it to; ``deployment/content.py`` and ``deployment/dashboard_review.py`` stay
  owned content and are not consumers of this field.
* **Coverage honesty.** A graph or alert naming a series the store cannot show is a fabricated
  guarantee, so ``loader.ModuleLoader`` proves the names this schema validates against store facade's facade
  and refuses or reports ``unverified`` — the rule :mod:`.loader` owns, because proof needs the store
  and this file must stay importable offline.
* **Multi-instance is compiled, not shipped.** :mod:`.compiler` ports v0.1's expansion rule with no
  shipped example, because a compiler with no consumer is how the second prototype library arrived.

Upgrade: how ``schema_version`` moves (quality bar's fifth artefact)
--------------------------------------------------------------
``module_version`` is a counter the operator owns and may bump freely; nothing reads it but a reader.
``schema_version`` is the contract, and it moves under exactly one rule: **a module file whose
``schema_version`` this file does not know is refused at load, never reinterpreted.** A field added
without changing the version (an optional key older loaders ignore) is a compatible move and needs no
bump; anything that changes what an existing key *means* — a new selector form, a new datapoint type,
a new alert mode's fields — bumps the integer, this docstring gains the row, and the old version stays
writable until the loader stops accepting it, which is a separate change with its own release note in
docs/CHANGELOG.md. There is no migration tool and no in-place rewrite: module files are declarations
in the operator's repository, so the upgrade recipe is *edit the file, run the loader's refusal set*
(``tests/test_modules_loader.py``) and let it name what moved.

Backup and restore, in one sentence (quality bar's fourth artefact): a module file is a declaration, so it is
backed up and restored with the operator's own repository and its inventories — nothing in this product
writes one, and restoring it does not need this package at all beyond the loader's refusal set.
"""
from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass
from typing import Any

from local_observe.platform import conditions, vocabulary
from local_observe.store import client as store_client

from . import select

#: The only module document shape this file validates. See the module docstring for how it moves.
SUPPORTED_SCHEMA_VERSION = 1

MODULE_KEYS = frozenset({'schema_version', 'name', 'module_version', 'description', 'applies_to',
                         'collection', 'datapoints', 'default_graphs', 'default_alerts', 'multi_instance'})
MODULE_REQUIRED = ('schema_version', 'name', 'module_version', 'applies_to', 'collection', 'datapoints')

COLLECTION_KEYS = frozenset({'receiver', 'interval_seconds', 'scrapers', 'resource_attributes'})
COLLECTION_REQUIRED = ('receiver', 'interval_seconds')
DATAPOINT_KEYS = frozenset({'name', 'unit', 'type', 'description'})
DATAPOINT_REQUIRED = ('name', 'unit', 'type')
GRAPH_KEYS = frozenset({'title', 'datapoints'})
GRAPH_REQUIRED = ('title', 'datapoints')
ALERT_KEYS = frozenset({'name', 'datapoint', 'mode', 'op', 'threshold', 'for_seconds',
                        'within_seconds', 'severity', 'summary'})
ALERT_REQUIRED = ('name', 'datapoint', 'mode', 'severity')
MULTI_INSTANCE_KEYS = frozenset({'discovery', 'instance_label'})
DISCOVERY_KEYS = frozenset({'source'})
DISCOVERY_REQUIRED = ('source',)

#: The datapoint shapes this contract admits. v0.1 shipped these two and this repo's store admits
#: histograms too, but no consumer here reads one: a third type is a decision with a rule behind it,
#: not a widening of a tuple.
DATAPOINT_TYPES = ('counter', 'gauge')
#: The condition modes a ``default_alerts`` entry may name. Three of the four are imported — alert conditions's
#: own tuple, so a mode added there is usable here with no edit in this file. The fourth,
#: ``band``, is restated because the only place it is spelled is ``platform/dynamic_bands.py``, whose
#: import chain reaches the anomaly producer and its HTTP client; a schema check must not cost that.
#: ``tests/test_modules_schema.py`` pins this tuple against both source files, so it cannot drift
#: silently — the ``topology.RELATION_SHAPE`` precedent for a bound this brief may not import.
BAND_MODE = 'band'
ALERT_MODES = tuple(sorted(tuple(conditions.MODES) + (BAND_MODE,)))
#: The four comparisons alert conditions can run, imported so a module cannot name a comparison no rule has.
ALERT_OPS = tuple(sorted(conditions.OPS))
#: The three severities intake admits, read from the one crosswalk that knows them
#: (``platform/vocabulary.ADMITTED_SEVERITIES``). No severity word is spelled in this file.
ALERT_SEVERITIES = vocabulary.ADMITTED_SEVERITIES
#: The modes whose verdict is a value comparison, and so carry ``op``/``threshold``.
VALUE_MODES = ('threshold',)
#: The mode judged by the clock against one deadline, which therefore carries ``within_seconds`` and
#  must not carry a duration stacked behind it — alert conditions's own rule, restated for a declaration.
CLOCK_MODE = 'absence'

#: A module name is also the first segment of the rule id an operator's overlay renders from it, so
#: every character must stay inside what ``platform/state.label`` admits. It is narrower than that on
#: purpose: lowercase only, so two operators do not get ``Host_CPU`` and ``host_cpu`` as two modules.
NAME_SHAPE = re.compile(r'^[a-z][a-z0-9._-]{0,63}$')
#: An OTel receiver, scraper or resource-attribute key as the collector spells it
#: (``hostmetrics``, ``prometheus/job-observe``, ``resource_id``).
OTEL_NAME_SHAPE = re.compile(r'^[a-z][a-z0-9._/-]{0,63}$')
#: The store's own selector shape, **imported and not restated**: a datapoint name is what
#: ``describe-metrics`` binds as ``metric_name``, so a name outside this shape could never even be
#: *asked* of the store. Sharing the pattern is the pin — a widening there arrives here with no edit,
#: and ``tests/test_modules_schema.py`` proves the two agree on examples rather than on source text.
DATAPOINT_NAME_SHAPE = store_client.SELECTOR
#: OTel's unit convention (``s``, ``1``, ``By``, ``{bytes}``, ``MiBy``), which is what a graph legend
#: repeats. Anything else is refused at load rather than shipped to a legend nobody can read.
UNIT_SHAPE = re.compile(r'^[A-Za-z0-9_%{}./-]{1,64}$')

MAX_DATAPOINTS = 64
MAX_GRAPHS = 16
MAX_ALERTS = 16
#: Series one graph may plot: the same ceiling as one config's rule count (``conditions.MAX_RULES``),
#: which is the point at which a panel stops being readable.
MAX_GRAPH_SERIES = 16
#: Scraper and resource-attribute names one fragment may carry: a small closed set upstream (the
#: scrapers a receiver names, not free text), so 32 is room with a bound, and an unbounded list is an
#: unbounded render.
MAX_SCOPED_NAMES = 32
MAX_TEXT_CHARS = 512
#: Characters allowed inside a word a refusal echoes back — the same posture as
#: ``platform/vocabulary._ECHO_SAFE`` (bounded, printable, short), over a set wide enough to hold a
#: real datapoint name. The reason is the same: these sentences can reach an HTTP error body.
_ECHO_SAFE = re.compile(r'^[A-Za-z0-9_.:/*%{}-]{0,64}$')


@dataclass(frozen=True)
class ValidationResult:
    """Whether one module document is admissible, and every reason it is not.

    ``errors`` holds one sentence per defect, each naming the offending field path. An empty tuple
    with ``ok=True`` is the only other shape; this function never raises and never returns a partial
    verdict.
    """

    ok: bool
    errors: tuple[str, ...]


def _echo(value: Any) -> str:
    """Quote *value* inside a refusal sentence only if it is short, bounded and echo-safe."""
    return repr(value) if isinstance(value, str) and _ECHO_SAFE.fullmatch(value) else "'?'"


def _is_text(value: Any, *, maximum: int = MAX_TEXT_CHARS) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= maximum


def _where(prefix: str, key: str) -> str:
    """Join a field path without leaving a leading dot on a top-level key."""
    return f'{prefix}.{key}' if prefix else key


def _unknown_keys(errors: list[str], document: Any, allowed: frozenset[str], prefix: str) -> None:
    for key in sorted(set(document) - allowed):
        errors.append(f'{_where(prefix, key)}: unknown field (this schema admits no additional property)')


def _whole_number(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_name(document: Any, errors: list[str], prefix: str, *, shape: re.Pattern[str] = NAME_SHAPE,
                what: str = 'name') -> None:
    value = document.get(what)
    if not isinstance(value, str) or not shape.fullmatch(value):
        errors.append(f'{_where(prefix, what)}: must be 1-64 characters matching {shape.pattern}')


def _check_text_field(document: Any, errors: list[str], prefix: str, key: str, *,
                      required: bool = False) -> None:
    value = document.get(key)
    if value is None:
        if required:
            errors.append(f'{_where(prefix, key)}: missing required field')
        return
    if not _is_text(value):
        errors.append(f'{_where(prefix, key)}: must be 1-{MAX_TEXT_CHARS} characters of non-blank text')


def _check_collection(collection: Any, errors: list[str]) -> None:
    """Validate the OTel fragment shape; it never validates what a collector would accept."""
    prefix = 'collection'
    if not isinstance(collection, dict):
        errors.append(f'{prefix}: must be a mapping of {", ".join(sorted(COLLECTION_KEYS))}')
        return
    _unknown_keys(errors, collection, COLLECTION_KEYS, prefix)
    for key in COLLECTION_REQUIRED:
        if key not in collection:
            errors.append(f'{prefix}.{key}: missing required field')
    if 'receiver' in collection:
        _check_name(collection, errors, prefix, shape=OTEL_NAME_SHAPE, what='receiver')
    if 'interval_seconds' in collection:
        interval = collection['interval_seconds']
        if not _whole_number(interval) or not 5 <= interval <= 86400:
            errors.append(f'{prefix}.interval_seconds: must be a whole number of 5..86400 seconds '
                          '(one scrape interval per day at the loosest, five seconds at the tightest)')
    for key in ('scrapers', 'resource_attributes'):
        if key not in collection:
            continue
        names = collection[key]
        if not isinstance(names, list) or not names:
            errors.append(f'{_where(prefix, key)}: must be a non-empty list of bounded collector names')
            continue
        if len(names) > MAX_SCOPED_NAMES:
            errors.append(f'{_where(prefix, key)}: at most {MAX_SCOPED_NAMES} names are allowed')
        seen: set[str] = set()
        for position, name in enumerate(names):
            if not isinstance(name, str) or not OTEL_NAME_SHAPE.fullmatch(name):
                errors.append(f'{prefix}.{key}[{position}]: must be 1-64 characters of a lowercase '
                              f'collector name ({OTEL_NAME_SHAPE.pattern})')
            elif name in seen:
                errors.append(f'{prefix}.{key}[{position}]: duplicate name')
            else:
                seen.add(name)


def _check_datapoints(datapoints: Any, errors: list[str]) -> tuple[str, ...]:
    """Validate the declared series and return their names for the cross-reference checks."""
    if not isinstance(datapoints, list) or not datapoints:
        errors.append('datapoints: must be a non-empty list of declared series')
        return ()
    if len(datapoints) > MAX_DATAPOINTS:
        errors.append(f'datapoints: at most {MAX_DATAPOINTS} series may be declared by one module')
    names: list[str] = []
    for position, datapoint in enumerate(datapoints):
        prefix = f'datapoints[{position}]'
        if not isinstance(datapoint, dict):
            errors.append(f'{prefix}: must be a mapping of {", ".join(sorted(DATAPOINT_KEYS))}')
            continue
        _unknown_keys(errors, datapoint, DATAPOINT_KEYS, prefix)
        for key in DATAPOINT_REQUIRED:
            if key not in datapoint:
                errors.append(f'{prefix}.{key}: missing required field')
        name = datapoint.get('name')
        if not isinstance(name, str) or not DATAPOINT_NAME_SHAPE.fullmatch(name or ''):
            errors.append(f'{prefix}.name: must be 1-128 characters matching {DATAPOINT_NAME_SHAPE.pattern} '
                          '(the shape the store binds as metric_name)')
        elif name in names:
            errors.append(f'{prefix}.name: duplicate datapoint name')
        else:
            names.append(name)
        unit = datapoint.get('unit')
        if not isinstance(unit, str) or not UNIT_SHAPE.fullmatch(unit):
            errors.append(f'{prefix}.unit: must match {UNIT_SHAPE.pattern} (an OTel unit token)')
        if datapoint.get('type') not in DATAPOINT_TYPES:
            errors.append(f'{prefix}.type: {_echo(datapoint.get("type"))} is not one of '
                          f'{", ".join(DATAPOINT_TYPES)}')
        _check_text_field(datapoint, errors, prefix, 'description')
    return tuple(names)


def _check_default_graphs(graphs: Any, names: tuple[str, ...], errors: list[str]) -> None:
    if graphs is None:
        return
    if not isinstance(graphs, list):
        errors.append('default_graphs: must be a list')
        return
    if len(graphs) > MAX_GRAPHS:
        errors.append(f'default_graphs: at most {MAX_GRAPHS} graphs may be declared')
    for position, graph in enumerate(graphs):
        prefix = f'default_graphs[{position}]'
        if not isinstance(graph, dict):
            errors.append(f'{prefix}: must be a mapping of {", ".join(sorted(GRAPH_KEYS))}')
            continue
        _unknown_keys(errors, graph, GRAPH_KEYS, prefix)
        for key in GRAPH_REQUIRED:
            if key not in graph:
                errors.append(f'{prefix}.{key}: missing required field')
        _check_text_field(graph, errors, prefix, 'title')
        refs = graph.get('datapoints')
        if refs is None:
            continue
        if not isinstance(refs, list) or not refs:
            errors.append(f'{prefix}.datapoints: must be a non-empty list of declared datapoint names')
            continue
        if len(refs) > MAX_GRAPH_SERIES:
            errors.append(f'{prefix}.datapoints: at most {MAX_GRAPH_SERIES} series per graph')
        for ref in refs:
            if ref not in names:
                errors.append(f'{prefix}.datapoints: {_echo(ref)} is not a declared datapoint')


def _check_default_alerts(alerts: Any, names: tuple[str, ...], errors: list[str]) -> None:
    if alerts is None:
        return
    if not isinstance(alerts, list):
        errors.append('default_alerts: must be a list')
        return
    if len(alerts) > MAX_ALERTS:
        errors.append(f'default_alerts: at most {MAX_ALERTS} alerts may be declared')
    seen: set[str] = set()
    for position, alert in enumerate(alerts):
        prefix = f'default_alerts[{position}]'
        if not isinstance(alert, dict):
            errors.append(f'{prefix}: must be a mapping of {", ".join(sorted(ALERT_KEYS))}')
            continue
        _unknown_keys(errors, alert, ALERT_KEYS, prefix)
        for key in ALERT_REQUIRED:
            if key not in alert:
                errors.append(f'{prefix}.{key}: missing required field')
        name = alert.get('name')
        if not isinstance(name, str) or not NAME_SHAPE.fullmatch(name):
            errors.append(f'{prefix}.name: must be 1-64 characters matching {NAME_SHAPE.pattern}')
        elif name in seen:
            errors.append(f'{prefix}.name: duplicate alert name')
        else:
            seen.add(name)
        if alert.get('datapoint') not in names:
            errors.append(f'{prefix}.datapoint: {_echo(alert.get("datapoint"))} is not a declared datapoint')
        mode = alert.get('mode')
        if mode not in ALERT_MODES:
            errors.append(f'{prefix}.mode: {_echo(mode)} is not a condition type that exists '
                          f'({", ".join(ALERT_MODES)}; platform/conditions.py and dynamic_bands.py)')
        else:
            _check_alert_shape(alert, mode, prefix, errors)
        if alert.get('severity') not in ALERT_SEVERITIES:
            errors.append(f'{prefix}.severity: {_echo(alert.get("severity"))} is not one of '
                          f'{", ".join(ALERT_SEVERITIES)} (platform/state.validate_event admits no other)')
        _check_text_field(alert, errors, prefix, 'summary')


def _check_alert_shape(alert: dict[str, Any], mode: str, prefix: str, errors: list[str]) -> None:
    """Which fields this mode can actually mean, mirroring ``conditions.Rule.__post_init__``.

    A field a mode ignores is worse than a field it refuses: an operator who writes
    ``within_seconds: 60`` on a threshold rule would read the alert as deadline-backed when nothing
    would ever watch the clock. The refusal is the message.
    """
    if mode in VALUE_MODES:
        if alert.get('op') not in ALERT_OPS:
            errors.append(f'{prefix}.op: a {mode} alert names one of {", ".join(ALERT_OPS)}')
        threshold = alert.get('threshold')
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) \
                or not math.isfinite(threshold):
            errors.append(f'{prefix}.threshold: a {mode} alert needs a finite numeric threshold')
    elif 'op' in alert or 'threshold' in alert:
        errors.append(f'{prefix}: a {mode} alert judges no numeric comparison, so op/threshold are refused')
    if mode == CLOCK_MODE:
        within = alert.get('within_seconds')
        if not _whole_number(within) or not 60 <= within <= 86400:
            errors.append(f'{prefix}.within_seconds: an absence alert needs one deadline, a whole '
                          'number of 60..86400 seconds')
        if 'for_seconds' in alert:
            errors.append(f'{prefix}.for_seconds: an absence alert has one deadline; a duration behind '
                          'a deadline is two numbers answering one question')
    elif 'within_seconds' in alert:
        errors.append(f'{prefix}.within_seconds: only an absence alert is judged by the clock')
    if 'for_seconds' in alert:
        duration = alert['for_seconds']
        if not _whole_number(duration) or not 0 <= duration <= 86400:
            errors.append(f'{prefix}.for_seconds: must be a whole number of 0..86400 seconds')


def _check_multi_instance(block: Any, errors: list[str]) -> None:
    """Validate the declaration the compiler will expand; discovery itself is never run here."""
    prefix = 'multi_instance'
    if not isinstance(block, dict):
        errors.append(f'{prefix}: must be a mapping of {", ".join(sorted(MULTI_INSTANCE_KEYS))}')
        return
    _unknown_keys(errors, block, MULTI_INSTANCE_KEYS, prefix)
    discovery = block.get('discovery')
    if discovery is None:
        errors.append(f'{prefix}.discovery: missing required field')
    else:
        if not isinstance(discovery, dict):
            errors.append(f'{prefix}.discovery: must be a mapping holding only `source`')
        else:
            _unknown_keys(errors, discovery, DISCOVERY_KEYS, f'{prefix}.discovery')
            for key in DISCOVERY_REQUIRED:
                if key not in discovery:
                    errors.append(f'{prefix}.discovery.{key}: missing required field')
            if 'source' in discovery:
                _check_name(discovery, errors, f'{prefix}.discovery', shape=OTEL_NAME_SHAPE, what='source')
    template = block.get('instance_label')
    if template is None:
        errors.append(f'{prefix}.instance_label: missing required field')
        return
    if not isinstance(template, str) or not template.strip():
        errors.append(prefix + '.instance_label: must be a non-empty template string, naming at least '
                      'one discovered field as {field}')
        return
    try:
        fields = instance_label_fields(template)
    except ValueError as exc:
        errors.append(f'{prefix}.instance_label: is not a parseable template ({type(exc).__name__})')
        return
    if not fields:
        errors.append(f'{prefix}.instance_label: names no instance field; expected at least one '
                      "'{field}' placeholder")
    for field in fields:
        if not field.isidentifier():
            errors.append(f'{prefix}.instance_label: placeholder {_echo(field)} is not a plain instance '
                          'field name (no positional, dotted or indexed references)')


def instance_label_fields(template: str) -> list[str]:
    """Return the field names an ``instance_label`` template references, in order.

    Raises:
        ValueError: The template is unparseable (an unbalanced brace), as ``string.Formatter`` reports
            it. The caller turns that into one field-named error; it never reaches a compiler.
    """
    return [name for _, name, _, _ in string.Formatter().parse(template) if name is not None]


def validate(document: Any) -> ValidationResult:
    """Check one parsed module document against the contract; never raise, name every defect.

    This is the conformance surface module contract exists to create: the loader's refusal set
    (``tests/test_modules_loader.py``) is the executable form of this contract, and every refusal a
    reviewer wants a guarantee about must be a case there and not a sentence here.
    """
    if not isinstance(document, dict):
        return ValidationResult(False, ('module: must be a mapping (a parsed YAML object)',))
    errors: list[str] = []
    _unknown_keys(errors, document, MODULE_KEYS, '')

    for key in MODULE_REQUIRED:
        if key not in document:
            errors.append(f'{key}: missing required field')

    version = document.get('schema_version')
    if version is not None and version != SUPPORTED_SCHEMA_VERSION:
        errors.append(f'schema_version: {_echo(version)} is not supported; this loader reads '
                      f'{SUPPORTED_SCHEMA_VERSION} only, and a document it does not know is refused '
                      'rather than reinterpreted')
    _check_name(document, errors, '', what='name')
    module_version = document.get('module_version')
    if module_version is not None and (not _whole_number(module_version) or module_version < 1):
        errors.append('module_version: must be an integer >= 1')
    _check_text_field(document, errors, '', 'description')

    if 'applies_to' in document:
        selector_errors, _ = select.selector_errors(document['applies_to'])
        errors.extend(selector_errors)

    if 'collection' in document:
        _check_collection(document['collection'], errors)
    names = _check_datapoints(document['datapoints'], errors) if 'datapoints' in document else ()
    _check_default_graphs(document.get('default_graphs'), names, errors)
    _check_default_alerts(document.get('default_alerts'), names, errors)
    if 'multi_instance' in document:
        _check_multi_instance(document['multi_instance'], errors)
    return ValidationResult(not errors, tuple(errors))


def datapoint_names(module: dict[str, Any]) -> tuple[str, ...]:
    """Return the datapoint names one *validated* module declares, in declaration order.

    Read-only helper for the loader and the compiler: a document that has not passed
    :func:`validate` may hold anything in ``datapoints``, so this returns what it can and asserts
    nothing about it.
    """
    names = [item.get('name') for item in module.get('datapoints') or ()
             if isinstance(item, dict) and isinstance(item.get('name'), str)]
    return tuple(names)


def referenced_datapoints(module: dict[str, Any]) -> tuple[str, ...]:
    """Return the datapoints this module *promises a surface for*: every graph and alert reference.

    This is the set the loader proves against the store. A declared datapoint no graph and no alert
    names is intent ("the collector will produce this"), and the loader reports it as such rather than
    refusing a module for a series that has never had a reason to exist in the store yet — the
    distinction, and the reason it is drawn there, are in :mod:`.loader`. Order is first-appearance,
    and duplicates across graphs collapse.
    """
    ordered: list[str] = []
    for graph in module.get('default_graphs') or ():
        if isinstance(graph, dict):
            ordered.extend(ref for ref in graph.get('datapoints') or () if isinstance(ref, str))
    for alert in module.get('default_alerts') or ():
        if isinstance(alert, dict) and isinstance(alert.get('datapoint'), str):
            ordered.append(alert['datapoint'])
    seen: set[str] = set()
    return tuple(name for name in ordered if not (name in seen or seen.add(name)))

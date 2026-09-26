"""What one catalogue entry may assert (module catalog): a manifest with nowhere to put a lie.

component independence's answer is a manifest — *"each component declares required capabilities, optional integrations,
and what remains usable when an integration is absent"* — and `docs/COMPONENTS.md` §3 has been selling
optional integrations (Portainer, CrowdSec, Gatus, the Zeek/Suricata/Falco row, HolmesGPT, the
identity-alert feed) with no file format that could say so. This is that format, narrowed until it can
only say true things.

**The one v0.1 field set this is *not*.** `legacy:catalog/manifest_schema.py` described a v0.1 module
bundle: `version` as `MAJOR.MINOR.PATCH`, `tags`/`device_classes` to browse by, and a `modules` list
holding either a ref to a `*.yaml` file in the entry directory or a whole **inline module mapping**.
Three of those fields cannot come here. An inline module mapping is a second copy of a module, which
is a second authority — the same defect `components/data/query-adapter/versions.json` names for an
image digest ("a copy of a digest is a second source of truth"). A `MAJOR.MINOR.PATCH` string exists to
be ordered against an installed version, and this package installs nothing, so the version grammar
would be decoration beside module contract's integer counter. And `device_classes` was v0.1's SNMP-shaped device
taxonomy; here the axis a reader browses by is the capability an entry needs.

The field contract, as it landed in ``schema_version`` 1
-------------------------------------------------------
Required, in the order a reader meets them:

* ``schema_version`` — the only value is ``1``, and a manifest this file does not know is refused,
  never reinterpreted: module contract's upgrade seam, reused rather than restated.
* ``name`` — :data:`modules.schema.NAME_SHAPE`, the *same compiled object* as a module name, so one
  shape governs both idioms. It must also equal its directory name; the registry checks that.
* ``entry_version`` — an integer >= 1, the author's own revision counter. Nothing in this package
  orders two entries by it, because nothing installs one.
* ``description`` — what the integration is, in bounded text. **No version numbers in it**: the scan
  below refuses a dotted version anywhere in the document, prose included.
* ``decided_by`` — a stable decision identifier documented in ``docs/DECISIONS.md``
  that authorised this integration. An entry that names no decision is a feature nobody decided, and
  this repository lets a decision outrank an agent's inference.
* ``capabilities`` — 1..8 names from :data:`CAPABILITIES`, which is the capability list of
  ``docs/ARCHITECTURE.md`` §2 slugged to the shape a manifest can hold. Capabilities and **not** host
  names, mount paths or service names are what an entry may require of a deployment: that is component independence's
  sentence, and it is also why a catalogue entry can travel (public upstream/development and public release authority:
  this repo is upstream, an
  operator's overlay is downstream).
* ``components`` — the pieces of *this tree* the entry touches, each with its own
  ``docs/COMPONENTS.md`` §2 **validation state** (`selected` / `experimental` / `validated`), its
  relationship to the integration, and its pins **by reference**. The state is what *this entry* claims
  about the combination it names; the component's own ``versions.json`` stays the authority for the
  component, and the registry refuses an entry that claims **more** than that file does (under-claiming
  is allowed and is what every seed here does).
* ``modules`` — references to module contract modules by ``name`` plus the minimum ``module_version`` the entry
  was written against. A reference, never an inline copy: the module file stays the one authority for
  what it collects.
* ``if_disabled`` — one sentence answering component independence's second half: what still works when this is absent.

No other key is admitted anywhere in the document, at any depth.

Two refusals exist because a catalogue can otherwise become marketing
---------------------------------------------------------------------
* **A pin may only be a pointer.** A component's images/versions are named as
  ``{"file": "components/<plane>/<name>/versions.json", "key": "gatus_image"}`` and resolved by
  :mod:`.registry` against that one file. `docs/COMPONENTS.md` §2's compatible-tuple rule exists to
  stop a second copy of a pin existing, and a manifest that quotes a tag would be that copy — worse,
  it would be a copy that survives the pin move and lies about what is installed. The structural fields
  are already incapable of holding one — each is shape-constrained and then proven — so
  :func:`inline_pin_hits` scans the **free-text** fields (``description``, ``if_disabled``,
  ``conformance_evidence``) for four pin shapes (a digest, a dotted version, an `name/repo:tag` image
  reference, a host name) and refuses naming the field. That includes prose: a
  description reading "pinned to 1.2.3" is the drift this rule exists to stop, which is why the
  sentence above says *no version numbers in the description*.
* **`validated` is not a word an entry may use freely.** quality bar's five artefacts are the bar for it, so
  a component reference claiming `validated` must name a `conformance_evidence` path inside this
  checkout, which the registry proves exists. `selected` and `experimental` need no evidence path
  because they claim no evidence — and a seeded entry that cannot show its artefacts must say
  `selected`, which is what every seed here does.

A reference is a lexical path before it is a filesystem one
-----------------------------------------------------------
Three fields above are paths (:data:`COMPONENT_PATH_SHAPE`, :data:`PIN_FILE_SHAPE`,
:data:`EVIDENCE_PATH_SHAPE`) and :mod:`.registry` joins each of them to a checkout root, so a *regex* is
not the boundary: a character class that admits ``.`` admits ``..``, which is how
``docs/../../../etc/passwd`` read as an evidence path, and ``$`` also matches before a trailing newline,
which is how ``components/control/platform/versions.json\n`` read as a pin file. Both of those reached
:mod:`.registry`, which joined them to the checkout and then *asked the filesystem about them* — and a
pin key that did not resolve quotes back the keys of the file it opened. :func:`lexical_reference`
therefore checks the whole string: absolute, drive/UNC/device form, backslash separator, empty or
repeated or trailing separator, any segment of dots alone (``.``, ``..``, ``...``), any segment ending in
a dot (which Windows strips before the name reaches the directory), and any control character. Every
path pattern is applied with :meth:`re.Pattern.fullmatch`, so no ``$`` is load-bearing. The alphabet each
shape admits is **unchanged** — a shipped reference parses exactly as it did — and what is no longer
admissible is a reference that leaves the checkout on its way in. The registry adds the half no lexical
check can see (a ``components/control`` symlink or junction can resolve elsewhere);
:func:`lexical_reference` is the half that runs without touching a filesystem at all.

The vocabulary question, and why a constant here is copied and not read
-----------------------------------------------------------------------
:data:`STATES` and :data:`CAPABILITIES` are **spelled in this file and pinned by tests** rather than
read out of `docs/COMPONENTS.md` §2 and `docs/ARCHITECTURE.md` §2 at runtime, for one reason: the
product may not depend on its own documentation tree being present, and a shipped wheel has no
guarantee of one. That is the same trade `modules/schema.py` documents for its `band` mode — restate
the value, then pin it where it cannot drift silently
(`tests/test_catalog_manifest.py::VocabularyPinnedToItsSource`).

What this file does **not** do
------------------------------
It never touches the filesystem (that is :mod:`.registry`), never parses YAML (a manifest is JSON:
v0.1's documented decision, which keeps this package at the stdlib floor beside `json` and the PyYAML
that module contract already needs for module files), never raises from :func:`validate`, and never validates a
*module* — a module reference is checked for existence and revision by the registry, and its content
belongs to `modules.schema`, which this file imports for its shapes and its `ValidationResult` rather
than forking.
"""
from __future__ import annotations

import re
from typing import Any

from local_observe.modules import schema as module_schema
from local_observe.modules.schema import ValidationResult

#: The only entry shape this file validates. A manifest whose version this is not is refused: the
#  upgrade rule is module contract's and is stated in its schema's docstring, not restated here.
SUPPORTED_SCHEMA_VERSION = 1

ENTRY_KEYS = frozenset({'schema_version', 'name', 'entry_version', 'description', 'decided_by',
                        'capabilities', 'components', 'modules', 'if_disabled'})
ENTRY_REQUIRED = ('schema_version', 'name', 'entry_version', 'description', 'decided_by',
                  'capabilities', 'components', 'modules', 'if_disabled')
COMPONENT_KEYS = frozenset({'path', 'state', 'relationship', 'pin', 'conformance_evidence'})
COMPONENT_REQUIRED = ('path', 'state', 'relationship')
PIN_KEYS = frozenset({'file', 'key'})
PIN_REQUIRED = ('file', 'key')
MODULE_REF_KEYS = frozenset({'name', 'min_module_version'})
MODULE_REF_REQUIRED = ('name',)

#: ``docs/COMPONENTS.md`` §2's validation-state vocabulary, quoted in that order. A fourth word would
#  be marketing, so this tuple is pinned against the document that defines it and against the
#  ``status`` values ``components/**/versions.json`` already uses.
STATES = ('selected', 'experimental', 'validated')
#: The one state that is a promise about evidence rather than about intent.
VALIDATED = 'validated'
#: How a referenced component relates to the integration. Closed, because "related to" would let a
#  reader infer that an entry deploys the thing it names — and nothing here deploys anything.
RELATIONSHIPS = ('engine', 'pin-holder', 'surface', 'intake')
#: The two relationships that assert this tree fixes a build for the integration, which is why each
#  one must carry a pin reference: "we run X" with no version named is a claim about a version.
PIN_BEARING = ('engine', 'pin-holder')

#: The infrastructure capabilities of ``docs/ARCHITECTURE.md`` §2, slugged. Copied and pinned by test,
#  for the runtime-dependency reason in the module docstring.
CAPABILITIES = ('ai-inference', 'backup-target', 'collection-network', 'configuration-source',
                'container-execution', 'durable-storage', 'home-hub-and-power', 'operator-access',
                'operator-endpoints', 'probes', 'secrets')

#: Counts, not suggestions: a manifest is a hand-written file read by a build, and an unbounded list
#  is an unbounded review. ``modules.schema``'s ceilings are the same kind of number.
MAX_COMPONENTS = 8
MAX_MODULE_REFS = 16
MAX_CAPABILITIES = 8
MAX_SENTENCE_CHARS = 320
MAX_TEXT_CHARS = module_schema.MAX_TEXT_CHARS
MAX_PATH_CHARS = 160
MAX_PIN_KEY_SEGMENTS = 6

#: An entry name is also a directory name, so it is module contract's module-name shape — the same compiled
#  object, not a copy of the pattern. Narrower than a filesystem name on purpose: lowercase only, so
#  two authors cannot ship ``Portainer`` and ``portainer`` as two entries.
NAME_SHAPE = module_schema.NAME_SHAPE
#: Stable decision identifier. Q and D prefixes are retained for schema compatibility.
DECISION_SHAPE = re.compile(r'^(?:Q|D)-[0-9]{1,3}[a-z]?$')
#: Exactly ``components/<plane>/<component>``: two segments, nothing else, so a reference cannot be a
#  file, a traversal or an absolute path.
COMPONENT_PATH_SHAPE = re.compile(r'^components/[a-z][a-z0-9._-]*/[a-z][a-z0-9._-]*$')
#: The two files in this repository that own an image pin (``docs/COMPONENTS.md`` §2,
#  ``components/data/query-adapter/versions.json``'s ``compatible_tuple`` note). At least one directory
#  segment is required: a file loose under ``components/`` belongs to no component.
PIN_FILE_SHAPE = re.compile(r'^components/(?:[A-Za-z0-9._-]+/)+(?:versions\.json|image-lock\.json)$')
#: A dotted object path inside a pin file. Object members only: a list position is not a reference,
#  because an index in a manifest is a promise about somebody else's ordering.
PIN_KEY_SHAPE = re.compile(r'^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*$')
#: Evidence is a file in this checkout, named root-relative, under a tree a shipped entry may point at.
EVIDENCE_PATH_SHAPE = re.compile(r'^(?:components|docs|examples|local_observe)/[A-Za-z0-9._-]+'
                                 r'(?:/[A-Za-z0-9._-]+)*$')
_SENTENCE_END = re.compile(r'[.!?](?:\s|$)')

#: The free-text fields a copied pin can arrive in. The structural fields are deliberately absent:
#  each is constrained to a shape that cannot hold a value (a path under ``components/``, a dotted key
#  whose segments start with a letter, a name in a closed vocabulary or an module contract module id) and is then
#  proven by :mod:`.registry` against the tree it names.
PIN_SCANNED_KEYS = ('description', 'if_disabled', 'conformance_evidence')

#: The four shapes a pin takes when it has been copied out of the file that owns it. Each is matched
#  against the fields above, so prose is as much a target as an evidence path.
INLINE_PIN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ('a content digest', re.compile(r'(?i)(?:sha[0-9]+:[0-9a-f]{6,}|\b[0-9a-f]{32,}\b)')),
    ('a dotted version number', re.compile(r'\b\d+\.\d+(?:\.\d+)?\b')),
    ('an image reference with a tag', re.compile(r'\b[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+\b')),
    ('a registry host or a fully qualified name', re.compile(
        r'(?i)\b(?:[a-z0-9-]+\.)?(?:docker\.io|ghcr\.io|quay\.io|gcr\.io|registry\.k8s\.io'
        r'|mcr\.microsoft\.com)\b|\b[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}\b')),
)
_ECHO_SAFE = re.compile(r'^[A-Za-z0-9_.:/*%{}-]{0,64}$')


def _echo(value: Any) -> str:
    """Quote *value* inside a refusal sentence only if it is short, bounded and echo-safe."""
    return repr(value) if isinstance(value, str) and _ECHO_SAFE.fullmatch(value) else "'?'"


def lexical_reference(value: Any) -> str | None:
    """Return why *value* cannot name a file inside one checkout, or ``None`` when lexically it can.

    A manifest path is joined to a root by :mod:`.registry` and then *asked about*, and the asking is
    the leak: :meth:`registry._check_pin` reports the keys of the file a pin pointer reached, so a
    reference that walked out of the checkout would put a stranger file's key names in a build log.
    This is the check that runs on the string, before any filesystem question, and it is deliberately
    not a regex over a character class:

    * a class that admits ``.`` admits ``..``, so the parent segment is refused **as a segment**, and
      every segment of dots alone with it, avoiding platform-dependent trailing-dot normalization;
    * ``$`` matches before a trailing newline, so a control character is refused here, where the
      refusal can say which kind it was, rather than by an anchor that also matches;
    * ``/`` and ``\\`` are separators on different platforms and ``:`` opens a drive, a device form or
      a URL scheme, none of which is a path inside a checkout. Two of those characters cannot even be
      named by the shapes' alphabet; refusing them here is what stops the shapes being the only thing
      standing between ``..`` and a joined path.

    The segment **alphabet** stays the shapes' job, so legitimate shipped grammar is untouched: a name
    may start with a dot, contain dots, or contain an underscore. What may not happen is climbing.
    """
    if not isinstance(value, str):
        return 'must be a path spelled as text'
    if not value:
        return 'names nothing (an empty path)'
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return ('holds a control character: a newline, a carriage return or a NUL inside a path is a '
                'terminator or an argument boundary, never part of a name')
    if value != value.strip():
        return ('begins or ends with whitespace, which a filesystem may trim and this reader cannot '
                'un-trim')
    if '\\' in value:
        return ('uses a backslash, which is a separator on Windows and part of a file name on POSIX; '
                'portable references use "/"')
    if ':' in value:
        return 'names a drive letter, a device form or a scheme rather than a path inside a checkout'
    if value.startswith('//'):
        return 'is a UNC or device form ("//server/share"), which is a location and not a relative path'
    if value.startswith('/'):
        return 'is an absolute path; a manifest reference is relative to the checkout the registry names'
    for segment in value.split('/'):
        if not segment:
            return 'has an empty segment (a repeated or trailing separator)'
        if segment in ('.', '..'):
            return ('has a "." or ".." segment: a reference names a file under the checkout and may not '
                    'climb out of it')
        if segment.rstrip('.') == '':
            return ('has a segment made of nothing but dots; dot segments and platform-dependent '
                    'trailing-dot normalization are refused')
        if segment != segment.rstrip('.'):
            return 'has a segment ending in a dot, which Windows strips before the name is looked up'
    return None


def _is_text(value: Any, *, maximum: int = MAX_TEXT_CHARS) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= maximum


def _where(prefix: str, key: str) -> str:
    """Join a field path without leaving a leading dot on a top-level key."""
    return f'{prefix}.{key}' if prefix else key


def _unknown_keys(errors: list[str], document: Any, allowed: frozenset[str], prefix: str) -> None:
    for key in sorted(set(document) - allowed):
        errors.append(f'{_where(prefix, key)}: unknown field (this manifest admits no additional property)')


def _check_text(document: Any, errors: list[str], prefix: str, key: str, *, maximum: int = MAX_TEXT_CHARS,
                what: str = 'non-blank text') -> None:
    if key not in document:
        errors.append(f'{_where(prefix, key)}: missing required field')
    elif not _is_text(document[key], maximum=maximum):
        errors.append(f'{_where(prefix, key)}: must be 1-{maximum} characters of {what}')


def _whole_number(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _walk_strings(value: Any, prefix: str = '') -> list[tuple[str, str]]:
    """Return every ``(field path, string)`` pair in a parsed manifest, in document order."""
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key in value:
            found.extend(_walk_strings(value[key], _where(prefix, str(key))))
    elif isinstance(value, list):
        for position, item in enumerate(value):
            found.extend(_walk_strings(item, f'{prefix}[{position}]'))
    elif isinstance(value, str):
        found.append((prefix or 'manifest', value))
    return found


def inline_pin_hits(manifest: Any) -> list[str]:
    """Name every free-text field in *manifest* that copies a pin instead of pointing at one.

    The answer is a list of field paths with the shape matched, never the matched text: echoing a
    digest back in an error would put a copy of the pin in the log line that reports the copy. Only
    :data:`PIN_SCANNED_KEYS` is read, for the reason written beside it.
    """
    hits: list[str] = []
    for path, text in _walk_strings(manifest):
        if path.rsplit('.', 1)[-1].split('[')[0] not in PIN_SCANNED_KEYS:
            continue
        for shape, pattern in INLINE_PIN_PATTERNS:
            if pattern.search(text):
                hits.append(f'{path}: {shape} appears in this manifest; a pin is referenced by '
                            f'"file" and "key" against components/**/versions.json and never quoted '
                            'here (a second copy of a pin is a second authority)')
                break
    return hits


def _check_sentence(document: Any, errors: list[str]) -> None:
    """``if_disabled`` must be exactly one sentence: component independence asks one question, not an essay."""
    if 'if_disabled' not in document:
        errors.append('if_disabled: missing required field')
        return
    value = document['if_disabled']
    if not _is_text(value, maximum=MAX_SENTENCE_CHARS):
        errors.append(f'if_disabled: must be 1-{MAX_SENTENCE_CHARS} characters of non-blank text')
        return
    if '\n' in value or '\r' in value:
        errors.append('if_disabled: must be one line; what still works without this integration is '
                      'one sentence, not a section')
        return
    endings = _SENTENCE_END.findall(value)
    if len(endings) != 1 or value[-1] not in '.!?':
        errors.append(f'if_disabled: must be exactly one sentence ending in a full stop '
                      f'({len(endings)} found)')


def _check_capabilities(document: Any, errors: list[str]) -> None:
    capabilities = document.get('capabilities')
    if capabilities is None:
        errors.append('capabilities: missing required field')
        return
    if not isinstance(capabilities, list) or not capabilities:
        errors.append('capabilities: must be a non-empty list of capability names from '
                      'docs/ARCHITECTURE.md section 2; a host name, a path or a service name is not '
                      'a capability and has nowhere to go in this manifest')
        return
    if len(capabilities) > MAX_CAPABILITIES:
        errors.append(f'capabilities: at most {MAX_CAPABILITIES} may be declared by one entry')
    seen: set[str] = set()
    for position, capability in enumerate(capabilities):
        prefix = f'capabilities[{position}]'
        if not isinstance(capability, str) or capability not in CAPABILITIES:
            errors.append(f'{prefix}: {_echo(capability)} is not a declared capability '
                          f'({", ".join(CAPABILITIES)})')
        elif capability in seen:
            errors.append(f'{prefix}: duplicate capability {capability!r}')
        else:
            seen.add(capability)


def _check_pin(pin: Any, prefix: str, errors: list[str]) -> None:
    if pin is None:
        errors.append(f'{prefix}.pin: missing required field; this relationship names a build, so it '
                      'must reference the file and key that pin it')
        return
    if not isinstance(pin, dict):
        errors.append(f'{prefix}.pin: must be a mapping of {", ".join(sorted(PIN_KEYS))} — a pointer '
                      'to a pin, never a pin value')
        return
    _unknown_keys(errors, pin, PIN_KEYS, f'{prefix}.pin')
    for key in PIN_REQUIRED:
        if key not in pin:
            errors.append(f'{prefix}.pin.{key}: missing required field')
    file_value = pin.get('file')
    problem = lexical_reference(file_value)
    if problem is None and not (isinstance(file_value, str) and PIN_FILE_SHAPE.fullmatch(file_value)):
        problem = ('not a path under components/ ending in versions.json or image-lock.json, the two '
                   'files that own a pin')
    if problem is not None:
        errors.append(f'{prefix}.pin.file: {_echo(file_value)} is refused — {problem}')
    key_value = pin.get('key')
    if not isinstance(key_value, str) or not PIN_KEY_SHAPE.fullmatch(key_value):
        errors.append(f'{prefix}.pin.key: must be a dotted object path matching {PIN_KEY_SHAPE.pattern} '
                      '(object members only, no list index)')
    elif len(key_value.split('.')) > MAX_PIN_KEY_SEGMENTS:
        errors.append(f'{prefix}.pin.key: at most {MAX_PIN_KEY_SEGMENTS} path segments')


def _check_component(component: Any, prefix: str, errors: list[str]) -> None:
    if not isinstance(component, dict):
        errors.append(f'{prefix}: must be a mapping of {", ".join(sorted(COMPONENT_KEYS))}')
        return
    _unknown_keys(errors, component, COMPONENT_KEYS, prefix)
    for key in COMPONENT_REQUIRED:
        if key not in component:
            errors.append(f'{prefix}.{key}: missing required field')
    path = component.get('path')
    problem = lexical_reference(path)
    if problem is None and not (isinstance(path, str) and COMPONENT_PATH_SHAPE.fullmatch(path)):
        problem = 'not a components/<plane>/<component> directory name'
    if problem is not None:
        errors.append(f'{prefix}.path: {_echo(path)} is refused — {problem}; a file, a traversal or an '
                      'absolute path is refused before any read')
    state = component.get('state')
    if state not in STATES:
        errors.append(f'{prefix}.state: {_echo(state)} is not a validation state that exists '
                      f'({", ".join(STATES)}, per docs/COMPONENTS.md section 2)')
    relationship = component.get('relationship')
    if relationship not in RELATIONSHIPS:
        errors.append(f'{prefix}.relationship: {_echo(relationship)} is not one of '
                      f'{", ".join(RELATIONSHIPS)}; "related to" is refused because a reader would '
                      'take it for "installed by this entry"')
    elif relationship in PIN_BEARING:
        _check_pin(component.get('pin'), prefix, errors)
    elif 'pin' in component and component['pin'] is not None:
        _check_pin(component['pin'], prefix, errors)
    evidence = component.get('conformance_evidence')
    if evidence is None:
        if state == VALIDATED:
            errors.append(f'{prefix}.conformance_evidence: a {VALIDATED} claim names the file that '
                          f'holds quality bar\'s five artefacts; no evidence path means {VALIDATED} is not '
                          'available to this entry')
        return
    if not _is_text(evidence, maximum=MAX_PATH_CHARS):
        errors.append(f'{prefix}.conformance_evidence: must be 1-{MAX_PATH_CHARS} characters of '
                      'non-blank text')
    else:
        problem = lexical_reference(evidence)
        if problem is None and not EVIDENCE_PATH_SHAPE.fullmatch(evidence):
            problem = ('not a root-relative path under components/, docs/, examples/ or '
                       'local_observe/')
        if problem is not None:
            errors.append(f'{prefix}.conformance_evidence: {_echo(evidence)} is refused — {problem}')


def _check_components(document: Any, errors: list[str]) -> list[str]:
    components = document.get('components')
    if components is None:
        errors.append('components: missing required field (an empty list says this entry touches '
                      'nothing in this tree, which is a statement worth making explicitly)')
        return []
    if not isinstance(components, list):
        errors.append('components: must be a list of component references')
        return []
    if len(components) > MAX_COMPONENTS:
        errors.append(f'components: at most {MAX_COMPONENTS} may be referenced by one entry')
    paths: list[str] = []
    for position, component in enumerate(components):
        prefix = f'components[{position}]'
        _check_component(component, prefix, errors)
        if isinstance(component, dict) and isinstance(component.get('path'), str):
            if component['path'] in paths:
                errors.append(f'{prefix}.path: duplicate component reference {component["path"]!r}')
            else:
                paths.append(component['path'])
    return paths


def _check_module_refs(document: Any, errors: list[str]) -> None:
    modules = document.get('modules')
    if modules is None:
        errors.append('modules: missing required field (use an empty list when the integration ships no modules)')
        return
    if not isinstance(modules, list):
        errors.append('modules: must be a list of module references; an inline module mapping is a '
                      'second copy of a module and is refused')
        return
    if len(modules) > MAX_MODULE_REFS:
        errors.append(f'modules: at most {MAX_MODULE_REFS} may be referenced by one entry')
    seen: set[str] = set()
    for position, reference in enumerate(modules):
        prefix = f'modules[{position}]'
        if not isinstance(reference, dict):
            errors.append(f'{prefix}: must be a mapping of {", ".join(sorted(MODULE_REF_KEYS))}; a '
                          'module is referenced by id, never embedded')
            continue
        _unknown_keys(errors, reference, MODULE_REF_KEYS, prefix)
        for key in MODULE_REF_REQUIRED:
            if key not in reference:
                errors.append(f'{prefix}.{key}: missing required field')
        name = reference.get('name')
        if not isinstance(name, str) or not NAME_SHAPE.fullmatch(name or ''):
            errors.append(f'{prefix}.name: must be 1-64 characters matching {NAME_SHAPE.pattern} '
                          '(the shape modules.schema admits for a module name)')
        elif name in seen:
            errors.append(f'{prefix}.name: duplicate module reference {name!r}')
        else:
            seen.add(name)
        if 'min_module_version' in reference:
            minimum = reference['min_module_version']
            if not _whole_number(minimum) or minimum < 1:
                errors.append(f'{prefix}.min_module_version: must be an integer >= 1, the lowest '
                              'module_version this entry was written against')


def validate(manifest: Any) -> ValidationResult:
    """Check one parsed entry manifest; never raise, name every defect in one answer.

    Filesystem truth — does the referenced component directory exist, does the pin key resolve, is the
    evidence path a file — is :func:`local_observe.catalog.registry`'s job and is deliberately absent
    here, so this function stays a pure document check a test can run on a dict.
    """
    if not isinstance(manifest, dict):
        return ValidationResult(False, ('manifest: must be a mapping (a parsed JSON object)',))
    errors: list[str] = []
    _unknown_keys(errors, manifest, ENTRY_KEYS, '')
    for key in ENTRY_REQUIRED:
        if key not in manifest:
            errors.append(f'{key}: missing required field')

    version = manifest.get('schema_version')
    if version is not None and version != SUPPORTED_SCHEMA_VERSION:
        errors.append(f'schema_version: {_echo(version)} is not supported; this reader accepts '
                      f'{SUPPORTED_SCHEMA_VERSION} only, and a document it does not know is refused '
                      'rather than reinterpreted')
    if 'name' in manifest:
        name = manifest['name']
        if not isinstance(name, str) or not NAME_SHAPE.fullmatch(name):
            errors.append(f'name: must be 1-64 characters matching {NAME_SHAPE.pattern} (a lowercase '
                          'directory name; the registry also requires it to equal that directory)')
    entry_version = manifest.get('entry_version')
    if entry_version is not None and (not _whole_number(entry_version) or entry_version < 1):
        errors.append('entry_version: must be an integer >= 1 (the author\'s own counter; nothing '
                      'installs an entry, so nothing orders it)')
    _check_text(manifest, errors, '', 'description')
    decided_by = manifest.get('decided_by')
    if decided_by is not None and (not isinstance(decided_by, str)
                                   or not DECISION_SHAPE.fullmatch(decided_by)):
        errors.append('decided_by: must name a stable decision ID such as D-101; '
                      'document the selection in docs/DECISIONS.md')

    _check_capabilities(manifest, errors)
    component_paths = _check_components(manifest, errors)
    _check_module_refs(manifest, errors)
    _check_sentence(manifest, errors)

    if not component_paths and 'modules' in manifest and isinstance(manifest['modules'], list) \
            and not manifest['modules']:
        errors.append('manifest: references no component and no module; an entry that names nothing in '
                      'this repository is a stub, not an integration')

    errors.extend(inline_pin_hits(manifest))
    return ValidationResult(not errors, tuple(errors))

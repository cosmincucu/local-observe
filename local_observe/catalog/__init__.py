"""The integration catalogue: a directory-backed registry that can describe an integration and no
more (module catalog).

component independence answered *"each component declares required capabilities, optional integrations, and what remains
usable when an integration is absent"*; `docs/COMPONENTS.md` §3 has a table of those optional
integrations (Portainer, CrowdSec, Zeek/Suricata/Falco, honeypot, Home Assistant, HolmesGPT, the
identity-alert feed) and §4 says *"each supported combination names exact versions and its acceptance
evidence"*. Between the two there was no artefact. This package is that artefact: one directory per
entry, one JSON manifest per entry, and a reader that refuses an entry which claims more than the tree
behind it can support.

The catalog connects product and deployment content: this repository ships the entries
it can stand behind, an operator's overlay repository holds the entries for the integrations it runs,
and both are checked by the same refusal set. "Git-backed" means v0.1 meant it — a plain directory
versioned by the repository around it. **No git operation happens in this package**: no fetch, no
clone, no revision read.

Three modules, three questions
------------------------------
* :mod:`.manifest` — *what may an entry assert?* The closed field set, and the two refusals that keep
  it honest: a version pin may only be a pointer into `components/**/versions.json`, and `validated`
  may only be said by an entry that names its conformance evidence.
* :mod:`.registry` — *is this entry true of this tree?* The directory walk, the two v0.1 disciplines
  (name equals directory name; validate everything before returning anything) and the resolution of
  every reference against a real checkout.
* (there is no third) — v0.1's `importer.py` is **not ported**, and the reason is the boundary below.

The boundary: what an entry can do in this build
------------------------------------------------
**Nothing, except make the registry refuse.** No code named by an entry is imported, no module file is
copied or installed, no path is written, no container is started, and **executing an entry is not
implemented here and has no CLI, no configuration variable and no plan attached to it**. The useful
half of v0.1's importer was the validation of a bundle's manifest; its other 243 lines staged module
files into a directory, wrote an `installed.json` index and replaced an installed entry's files in
place. This repository's posture is no dynamic import in the product path and fail-closed on bounded
inputs, and an installer would additionally need a decision about who authorises a third-party bundle
at all — which is a Q-item, not a port. Nobody should discover that later, so it is stated here, in the
package docstring, in `docs/STRUCTURE.md`'s row and in the entry-level README rather than only in a
report.

What an entry *is* good for, today: a build or authoring tool — a portal tile that lists what the
installation could enable, a CI job that refuses a release whose catalogue names a component that no
longer exists, an operator's review of their own overlay. **No product runtime path reads it**: the
platform serves no catalogue route, `platform/cli.py` has no command for it, and that is why
`local_observe/platform/README.md` gains no line. Module *content* still belongs wholly to
:mod:`local_observe.modules`: this package references modules by id and revision and validates nothing
about them beyond existence and revision, because module contract's schema is the one module contract this
repository has.
"""
from __future__ import annotations

from .manifest import (CAPABILITIES, ENTRY_KEYS, INLINE_PIN_PATTERNS, RELATIONSHIPS, STATES,
                       SUPPORTED_SCHEMA_VERSION, VALIDATED, inline_pin_hits, validate)
from .registry import (DEFAULT_REPO_ROOT, MANIFEST_FILENAME, CatalogEntry, CatalogError,
                       CatalogRegistry, ComponentRef, ModuleRef, Pin)

__all__ = [
    'CAPABILITIES',
    'CatalogEntry',
    'CatalogError',
    'CatalogRegistry',
    'ComponentRef',
    'DEFAULT_REPO_ROOT',
    'ENTRY_KEYS',
    'INLINE_PIN_PATTERNS',
    'MANIFEST_FILENAME',
    'ModuleRef',
    'Pin',
    'RELATIONSHIPS',
    'STATES',
    'SUPPORTED_SCHEMA_VERSION',
    'VALIDATED',
    'inline_pin_hits',
    'validate',
]

# Reference integration catalogue

Three shipped entries (`local_observe/catalog/` is the reader; this directory is the content):

| Entry | Decided by | Capabilities it requires | Components it names | State claimed |
|---|---|---|---|---|
| [`crowdsec-decisions`](crowdsec-decisions/entry.json) | threat detection engine (auto-block authority, community blocklist dependency) | `container-execution`, `durable-storage`, `secrets` | `components/control/platform` (`intake`) | `selected` |
| [`gatus-synthetics`](gatus-synthetics/entry.json) | gatus for synthetics | `container-execution`, `collection-network`, `durable-storage`, `probes`, `secrets` | `components/control/synthetics` (`engine`, pinning `image`) | `selected` |
| [`portainer-console`](portainer-console/entry.json) | cockpit and portainer | `container-execution`, `operator-access` | `components/control/homepage` (`surface`) | `selected` |

Every one is `selected`, which in `docs/COMPONENTS.md` §2's vocabulary means *chosen and not validated
here*. That is the honest ceiling for all three: none of them has a conformance recipe that has run, so
none may say `validated`, and `portainer-console` could not honestly say `experimental` because nothing
of Portainer is implemented here. The catalogue's purpose is to make that state sayable in a file rather
than inferable from prose.

## What an entry is, and what it is emphatically not

An entry is a **declaration**: this integration exists, it needs these capabilities from your
deployment, it touches these pieces of this repository, its images are pinned in that file under that
key, and this is what still works without it.

It is not an installer, and there is no installer. **No code named by an entry is imported, nothing is
copied, written, started or activated, and executing an entry is not implemented** — v0.1's importer was
deliberately not ported (`local_observe/catalog/registry.py` states the boundary, and
`tests/test_catalog_registry.py::NoExecutionBoundaryTests` fails if a write, an exec or a subprocess
ever arrives in the package). Today an entry can only ever do one thing: **make the registry refuse**.

It names no host, no path outside `components/`, no endpoint and no credential. What an integration
requires of a deployment is expressed as a *capability* (`docs/ARCHITECTURE.md` §2), which is why one
entry can be read by a stranger: `docs/COMPONENTS.md` §3's integrations are decisions, not this
estate's services.

## Checking a registry

```python
from pathlib import Path

from local_observe.catalog.registry import CatalogRegistry

registry = CatalogRegistry(Path('examples/catalog'), repo_root=Path('.'))
for entry in registry.entries():                      # every defect, or nothing at all
    print(entry.name, entry.decided_by, entry.capabilities)
    for component in entry.components:
        print('   ', component.path, component.state, component.pin)

print([entry.name for entry in registry.by_capability('probes')])
print([entry.name for entry in registry.by_state('validated')])   # empty, and honestly so
```

`repo_root` is the checkout the references inside an entry are relative to; it defaults to the product
checkout this package was imported from. An operator registry pointing at their own tree passes their
checkout, which is what makes "does this entry still describe my tree?" a question you can ask in CI. A
module reference additionally needs `modules=` — the directory `local_observe/modules/loader.py` reads.
Omit it and any entry that names a module is **refused**, not reported as unresolved.

## Refusals worth knowing before you write one

The executable list is `tests/test_catalog_manifest.py` (the field contract) and
`tests/test_catalog_registry.py` (the directory and the references).

## Reference confinement, in one paragraph

Every path an entry may name (`components[].path`, `pin.file`, `conformance_evidence`) is checked as a
**whole string** before it is joined to a checkout, and the joined result is checked as a **resolved
path** before anything is asked about it. That is the whole contract, and the reason it is stated twice
is that a regex over a character class is not a boundary: `.` is a legal character in a segment, so `..`
was a legal segment, and `$` matches before a trailing newline. Refused as a reference: an absolute path,
a drive letter, a `//server` or device form, a `\` separator, an empty or repeated separator, a `.` or
`..` segment, a segment of dots alone, a segment ending in a dot (Windows strips it and lands somewhere
else), and any control character — a trailing newline included. What survives is the shipped grammar: a
name may start with a dot, contain dots, hyphens or underscores, and sit as deep as it likes. Only
climbing left the grammar, and every shipped seed still parses unchanged.

The reader also refuses to quote what it refused: a confinement refusal names the reference and the
configured root, never the outside location the reference resolved to, and never a key, a status word or
a byte from the file it would have reached. What this does **not** claim: protection against a link
swapped in *after* the check (nothing here holds a directory handle open across the read), or against a
`repo_root`, a registry root or a module directory that an operator pointed somewhere odd — containment
is *relative to* those three, not of them.

## Adding a fourth entry

Downstream, the same rules apply to an operator's own registry directory (public upstream, development and public release authority, deployment separation): entries for
integrations this repository does not ship belong in the operator's repository, versioned by it, checked
by this same reader — the registry performs no git operation and fetches nothing, so "git-backed" means
only that the directory around it is versioned.

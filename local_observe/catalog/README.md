# Integration catalogue

The manifest behind component independence's sentence (module catalog): *each component declares required capabilities, optional
integrations, and what remains usable when an integration is absent.* `docs/COMPONENTS.md` §3 lists those
optional integrations and §4 says every supported combination names its versions and its acceptance
evidence; between the two there was no artefact. This is it — a directory-backed registry ("git-backed"
in the sense of a plain directory versioned by the repository around it: **no git operation happens
here**), plus the reader that refuses an entry which claims more than the tree can support.

- `manifest.py`: **the contract copy** — the closed field list, why a pin is only ever a `{file, key}`
  pointer into `components/**/versions.json`, why `validated` cannot be said without an evidence path,
  and where the three vocabularies come from (copied here, pinned to `docs/COMPONENTS.md` §2 and
  `docs/ARCHITECTURE.md` §2 by test, because the product may not read its own docs at runtime).
- `registry.py`: the directory. Name equals directory name, everything validated before anything is
  returned, every reference proven against a checkout — component directory, pin file and key, evidence
  file, and module id/revision resolved by running `modules.loader.ModuleLoader` itself.

**There is no command.** The package is imported by a build or an authoring tool, not run:
`platform/cli.py` has no subcommand for it and no product runtime path reads an entry, which is why
`local_observe/platform/README.md` carries no line for it either.

## The boundary, because it is where a reader looks in the wrong file

**An entry can do one thing: make the registry refuse.** Nothing named by an entry is imported, nothing
is installed, copied, written, started or activated, and **executing an entry is not implemented** —
v0.1's `importer.py` (staging, an `installed.json` index, in-place replacement) was not ported, and an
installer would additionally need an authorisation decision `docs/DECISIONS.md` does not contain.
`tests/test_catalog_registry.py::NoExecutionBoundaryTests` fails if an `exec`, an `importlib`, a
`subprocess` or a write ever arrives in this package, so the boundary cannot rot quietly.

Module *content* stays entirely with [`local_observe/modules/`](../modules/README.md): an entry references
a module by id and minimum revision and asserts nothing else about it. That reference is a counter and
not a content digest — `modules.schema` has no digest to name, and `module_version` is a revision the
operator may bump freely — so "this entry needs *that text*, not merely that revision" is not sayable in
this format yet. Making it sayable needs a digest in module contract's schema, which is a decision and not an
edit made from this package.

## Checking a registry

The operator-facing half — the code snippet, the refusal table, and how to add a fourth entry — is
[`examples/catalog/README.md`](../../examples/catalog/README.md); the shipped entries are
[`crowdsec-decisions`](../../examples/catalog/crowdsec-decisions/entry.json),
[`gatus-synthetics`](../../examples/catalog/gatus-synthetics/entry.json) and
[`portainer-console`](../../examples/catalog/portainer-console/entry.json). The conformance artefact is
the refusal set: `tests/test_catalog_manifest.py` (the field contract) and
`tests/test_catalog_registry.py` (the directory, the references, the seeds walked against this checkout).

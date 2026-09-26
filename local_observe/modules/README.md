# Monitoring modules

The block format (module contract): what a "module" is when `docs/COMPONENTS.md` §3 and deployment baseline say *blocks*.
No command line in this wave — the package is imported, not run (`platform/cli.py` is not this unit's
file), and nothing here writes, installs or renders anything.

- `schema.py`: **the contract copy** — the field list, why it is an explicit validator and not a
  JSON Schema file, how `schema_version` moves (upgrade) and the one-sentence backup/restore answer.
- `select.py`: `applies_to`. Declared UUIDs and indexed aliases, nothing else; the grammar and the
  v0.1 rule string it refuses are documented there.
- `loader.py`: reads a directory all-or-nothing, resolves the selector against a built inventory
  index, proves each referenced datapoint through `local_observe/store`'s `describe`, and reports
  `unverified`/`unchecked` where it could not check instead of passing it.
- `compiler.py`: multi-instance expansion (one datapoint set per discovered row), shipped with its
  refusal set and no worked example.

The operator-facing half — what to do with a module file, the refusal table in prose, and the one
thing the shipped example does not claim — is
[`examples/modules/README.md`](../../examples/modules/README.md); the worked example is
[`host-metrics.yaml`](../../examples/modules/host-metrics.yaml). The conformance artefact is the
refusal set: `tests/test_modules_schema.py`, `tests/test_modules_select.py`,
`tests/test_modules_loader.py`, `tests/test_modules_compile.py`.

Boundaries, restated because they are where a reader looks in the wrong file: `default_graphs` is a
declaration for the operator's own dashboard repository and **no product code renders it** (deployment separation, public upstream);
`collection` is an OTel fragment the operator's overlay renders into the pinned agent's config, which
`scripts/check_foundation.py`'s `check_collector` is the only thing that can prove; and module catalog's
catalogue will validate bundles *against this schema* without gaining an install path from it.

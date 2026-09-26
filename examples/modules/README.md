# Reference monitoring modules

One worked example of the block format (module contract): [`host-metrics.yaml`](host-metrics.yaml), declaring
the host metrics the pinned Linux collector already scrapes. The contract itself is
[`local_observe/modules/`](../../local_observe/modules/) — start at `schema.py` for the field list,
`select.py` for what `applies_to` may say, and `loader.py` for what a module is required to prove.
This file is the operator-facing half: what to do with a module file.

## What a module is not

It does not deploy anything. It names no endpoint, path or credential and has no field where one could
go. It is not a dashboard: `default_graphs` is a declaration your own dashboard repository consumes,
and no product code renders a panel from it (deployment separation, public upstream). And the loader is not an installer — see
`local_observe/modules/__init__.py` for what module catalog (the catalogue) will and will not inherit from here.

## Checking a module file

Build an inventory index, then load the directory over it:

```python
from pathlib import Path

from local_observe.inventory import index, validation
from local_observe.modules.loader import ModuleLoader

declared = validation.read_document(Path('examples/inventory/declared.yaml'))
index.build(declared, 'inventory.db', revision='my-declaration-1')

loader = ModuleLoader('examples/modules', index_path='inventory.db')   # store=/window= optional
for name in [module['name'] for module in loader.load()]:
    print(name, [assignment.as_dict() for assignment in loader.assignments()])
print(loader.summary()['coverage'])
```

With no `store` the module still loads and every referenced series is reported as `unchecked` — a
stated gap, never a pass. Passing `store=` plus `window=` is what turns the datapoint proof from a
statement into a check; see the refusal table below for what each answer costs.

A refusal is one `ModuleLoadError` naming the file and **every** defect in it, so a first draft is one
round trip, not six. The refusals worth knowing before you write one:

| You wrote | What happens |
|---|---|
| `applies_to: "kind=host AND hostname=probe-1"` | Refused. v0.1's rule string is not this grammar; name each resource by `id` or by an indexed `alias`. |
| `applies_to: {any_of: [{alias: {type: hostname, value: not-declared}}]}` | Refused: the term names no declared resource. A module that binds nothing promises coverage nobody declared. |
| a graph or alert naming a datapoint the module never declared | Refused at load, before any store is asked. |
| a graph or alert naming a declared datapoint **whose series the store does not have** | Refused, when a `store` and a `window` were supplied and the store answered. |
| a datapoint no graph and no alert references | **Loaded**, and reported as `intent`. The module is what turns collection on, so its brand-new series cannot already be in the store. |
| the store unreachable | **Loaded**, reported `series: unverified` with one WARNING. Never a pass. |
| `severity: error` | Refused. Intake admits `info`, `warning`, `critical` — v0.1's five-severity ladder has no encoding here. |
| `mode: band` with `op: ">"` and a `threshold` | Refused: a learned band has no fixed line to compare against. |
| a second file with the same `name` | Refused, naming the file that claimed it first. |
| `module.yml`, or a subdirectory beside your modules | Refused. A file the loader skipped is a module you think is enabled. |

The executable form of that table is `tests/test_modules_loader.py` (the refusal set) and
`tests/test_modules_select.py` (the selector grammar).

## Upgrade and backup, in two sentences

`module_version` is your own counter and nothing reads it; `schema_version` is the contract, a loader
refuses a document whose version it does not know rather than reinterpreting it, and moving it follows
the rule in `local_observe/modules/schema.py`. Module files are declarations, so they are backed up
and restored with your repository — restoring one needs no product state at all, only the refusal set
to re-check it.

## The one thing this example does not claim

`host-metrics.yaml` declares **one** datapoint. The other five scrapers it lists are enabled in
`components/data/agent-linux/collector.yaml`, but their series names are written nowhere in this
repository, and this repo's own store probe hedges between two spellings of even the one it does name
— `scripts/conformance_linux.py` queries `metric_name IN ('system.cpu.time','system_cpu_time')`, which
means the SigNoz-side normalisation has never been settled here. So if this module refuses to load on
your install with a store present, check which spelling your store holds before assuming the agent is
silent, and treat "add the remaining host scrapers" as a card with a measured store read in it rather
than a transcription job.

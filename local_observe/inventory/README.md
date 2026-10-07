# Inventory

Authoritative declarations, immutable derived indexes and review-only discovery.
Run `python -m local_observe.inventory --help` or the installed `lo-inventory`.

- `validation.py` and `schemas/`: strict declaration parsing and canonical
  hashes, and `validation.is_secret_key` is the one credential-name screen —
  `check_attributes` refuses such an attribute and `local_observe.log` re-exports
  the same function for redaction, so the two cannot drift apart.
- `index.py`: build/query versioned SQLite snapshots; preserve UUIDs and aliases.
- `discovery.py`, `docker_provider.py`, `sweep_provider.py`, `kube_provider.py`,
  `worker.py`: observations from scoped providers, drift and durable proposals;
  discovered data never silently replaces declared intent.
- `forge.py`: scoped reviewed-PR integration, separate from declaration promotion.
- `api.py`: optional authenticated inventory reader.

## What a declared resource carries

`schemas/declared.json` closes the resource object
(`additionalProperties: false`) and requires `id`, `kind`, `name`, `aliases`,
`attributes` and `relations`; `credential_refs` and `owner` are the two
optional fields. The built index stores exactly `id, kind, name, attributes,
credential_refs, owner` in `resources` (`index.py`), and every read of a
declared resource goes through that index.

`owner` is one bounded string — at least one character, at most 128, a leading
alphanumeric followed by `[A-Za-z0-9._@+ -]` — naming the on-call identity the
operator's overlay declares: a team, an account, a mailbox-shaped string.
Line breaks are refused, including a final newline; validation requires the
entire string to use the permitted characters. It
is never a hostname and never inferred from one; an alias says how a resource
is *found*, and who is woken when it breaks is a different claim.
`platform/presentation.py::owner_info` reads that column first and prints it
as declared. A resource declaring only the older `attributes['owner']` still
routes, and its label names the spelling it came from and asks for the typed
one; `attributes` is an open map of scalars, so an owner declared there may be
a number or a boolean and the view says "not a name" rather than printing it.
correlation followups drafted the typed field on its own and withdrew it: the field, the column
and the read order landed together in typed inventory records (2026-09-10), because a schema
field the build drops is an owner declared and never shown.

**A built index is at schema version 2** (`index.SCHEMA_VERSION`, written into
SQLite's `user_version`). Version 1 has no `owner` column, so reading one
would answer "No owner declared" for a resource whose operator did name an
owner. `index.readonly()` refuses it instead, in a sentence that names the
fix: rebuild from the declaration with `lo-inventory build`. Nothing is
migrated in place — the index is derived data, every byte of it reproducible
from the declaration, which is cheaper and safer than a migration path for a
file the operator never edits. `build()` lands on the stale file's own path:
it replaces an index of this product at any schema version and still refuses
to overwrite a file that is not one. Version 1 files cannot be read at all, so
there is no window in which an old index serves an old answer.

## The provider contract

A discovery source implements `discovery.Provider`: `observe()` returns
`Observation` values and `snapshot()` returns those observations sealed by
`discovery.snapshot()` into the document `discovery.ingest` appends. Those are
the only two verbs, and no provider takes an index, a path, a client or a
connection — a source cannot be handed something to write to. An `Observation`
carries what was seen (source, observed_at, aliases, attributes, evidence, and
optionally kind, name and a resource UUID *echoed from an operator's own label*);
it carries no decision. `index.resolve` matches identity, `drift` compares
against declarations, `propose` writes a review file and `forge.publish` opens
the pull request — all of them driven by `worker.py`, never by a provider.
Nothing between a provider and a human merge writes a declaration, and
`tests/test_discovery_providers.py` enforces that by reading each provider's
syntax tree (with a positive control proving the reader works).

Each source reads the least its purpose allows, through a named allowlist. The
Docker read asks the daemon for five fields (`FIELDS` in `docker_provider.py`):
id, state, project, service and the `local-observe.resource_id` label — so
`Config.Env`, where an operator's secrets sit, is never transferred. The
Kubernetes source reads seven paths plus container image names (`KUBE_FIELDS`
and `IMAGES_PATH` in `kube_provider.py`) out of a listing the operator captured
elsewhere; annotations, `env`/`envFrom`, image-pull and secret volumes, service
accounts, scheduling fields and registry digests are dropped, and the listing is
injected rather than fetched — this product holds no cluster client. The sweep
source holds no prober either: it enumerates ranges that must be IPv4 CIDR
notation inside RFC 1918 *and* inside the operator's declared sweep allowlist,
within a bound of 4096 addresses, and refuses the plan before probing. A range
outside those gates, or written with host bits set, is an error and never a
silently narrowed scan. Real ranges live in operator configuration; the only
address a shipped file names is the synthetic naming placeholder (`10.11.0.0/24`, commented
in `examples/inventory/observed.yaml`).

Silence is aged, not deleted. `discovery.ageing()` reports what a source stopped
seeing beyond a grace window, with the `observed_at` and evidence of the last
time it saw it, and every entry says `removed: false` — the observed plane is
append-only and declarations are human-owned. A source may only make that claim
when its newest snapshot is fresh, successful and `complete`; a stale, failed or
partial read returns a status (`source_stale`, `source_unavailable`,
`coverage_incomplete`) and an empty list, because "my probe broke" and "nothing
is there" are different answers. A fourth refusal caps the round: at most
`max_aged_percent` of the observations this source has ever been seen to report
(default 50, floored at one so a single vanished host can still age) may go
silent in one go, and a round that would age more answers `ageing_capped` with
counts and an empty list — a prober that answers "no" for every address looks
exactly like an empty network, so a round over the cap says so and concludes
nothing. Docker and Kubernetes therefore read with `complete: false`; the sweep
seals `complete: true` for a plan it probed in full, but it skips a silent
address rather than raising, so its conclusion is bounded by
`max_aged_percent` rather than by the plan.

Widening any of those three allowlists widens what leaves someone's host or
cluster, so it is a reviewed change to this section, to the module docstring and
to the pinned allowlist literal in the provider tests — in one PR, never a
feature flag.

The private repo owns declarations. Index snapshots are derived artifacts, not
the source of truth. Recovery must bind a rebuild to the exact declaration
revision and compare its contents. Pending discovery/proposal state is not
disposable merely because the inventory index can be rebuilt.

## Exporting to LogicMonitor

`logicmonitor.py` keeps a LogicMonitor portal's device list in step with the
declaration, in one direction only. LogicMonitor never feeds anything back into
the inventory, and the export never deletes a LogicMonitor device.

```bash
lo-inventory build declared.yaml --output inventory.db --revision "$(git rev-parse HEAD)"
lo-inventory export-logicmonitor --index inventory.db \
  --config logicmonitor-export.json --token-file /run/secrets/logicmonitor-bearer
```

Without `--apply` the command lists the changes it would make and writes
nothing to the portal. Review that output, then repeat with `--apply`. The token
file holds a LogicMonitor Bearer API token for a user allowed to read and manage
devices. The configuration (see `examples/inventory/logicmonitor-export.json`)
names the portal, the attributes copied as properties, the change limit, and
whether and where new devices may be created.

Each declared resource is carried as properties with the configured prefix
(`lo.` by default): `lo.resource_id`, `lo.kind`, `lo.owner` and one property per
listed attribute. LogicMonitor dynamic groups and alert rules can then select on
them. For example, a group with `lo.monitoring == "priority"` collects the devices
the operator cares about most, and devices whose `lo.presence` says absence is
normal can be left out of dead-device alerting.

How the export pairs resources with devices, strongest first:

1. A device whose `lo.resource_id` names the resource.
2. An explicit `adopt` pin in the configuration (resource UUID → device id).
3. Exactly one device whose display name or polling address matches the
   resource's name, a `hostname` or `ip` alias, or its `hostname_reported`
   attribute. Names are compared without case, spacing, punctuation or DNS
   domain. If a device matches two resources, neither adopts it.
4. A match on the `ip_observed` attribute alone, a DHCP lease, is only listed for
   review: a stale device at a reused address is a different machine. Confirm it
   by adding a pin.
5. A resource with no candidate is created only when `create.enabled` is true,
   it satisfies `create.when`, and it has a host name or address to poll.

A matched device gets the resource's name as its display name (`rename`, on by
default) unless another device already uses that name. Devices that claim a
resource the declaration no longer holds are reported as orphans and left alone.
`--apply` refuses a plan with more changes than `max_changes`. Updates use
`opType=replace`, so properties the export does not manage are kept.

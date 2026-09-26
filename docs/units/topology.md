# Unit: Topology

**File(s):** `local_observe/topology.py` · **Tests:** `tests/test_topology.py`,
`tests/test_topology_observed.py` · **Labels:** `local_observe/platform/presentation.py`
(`dependency_info`, the incident view's one topology section)

## Purpose

Turn the declared `relations` of one built inventory index into the two questions an incident
raises — *what does this resource depend on* and *what else breaks if it breaks* — without ever
becoming a second source of truth about what the edges are.

## Public API

`Topology(index_path, *, depth=DEFAULT_DEPTH, max_rows=MAX_ROWS)` — read-only questions over one
built index. It opens the index read-only per call (`inventory.index.readonly`, which re-validates
the application id and schema version every time) and holds no handle, no cache and no copy.

- `revision() -> dict` — `declaration_revision`, `declaration_sha256`, `built_at`, `schema_version`,
  read out of the index's own `build_metadata`. An index that cannot name its declaration is refused
  rather than answered with a null revision.
- `declared_edges(*, resource_id=None, relation=None, max_rows=None) -> dict` —
  `{'plane': 'declared', 'edges': [DeclaredEdge], 'truncated': bool, 'revision': dict}`.
  Here `truncated` can only mean the row bound: a single-hop read has no depth to cut.
- `edges_for(resource_id, *, max_rows=None) -> dict` — one resource's neighbourhood in one index
  open: `depends_on` (what it depends on) and `depended_on_by` (what depends on it), each bounded
  the same way.
- `upstream(resource_id, depth=None, *, max_rows=None) -> dict` — everything the id transitively
  depends on. Nodes carry `depth`, `via` (the neighbour reached first, at the shortest distance),
  `relation`, `kind`, `name` and `declaration_revision`; `depth_limit` and `depth_reached` say how
  far the call looked and how far it got, and `truncated`/`truncated_by` say whether a bound cut
  the answer and which one (see *Three bounds, three names*).
- `impact(resource_id, depth=None, *, max_rows=None) -> dict` — everything that transitively
  depends on the id: what breaks if it breaks. Same shape and the same truncation vocabulary.
- `shortest_path(a, b, depth=None) -> dict` — `status` is one of four:
  `found` (path plus one labelled `DeclaredEdge` per hop),
  `absent` (the search closed on its own, with no cut anywhere in it, and `b` is not reachable from
  `a` in the depends-on direction),
  `depth_exceeded` (the hop bound was reached with an edge still unexplored past the frontier) and
  `incomplete` (a row or node bound cut one of the levels, so neither the absence nor the length of
  a path is quotable). Only `found` and `absent` carry `complete: True`. A `found` also means
  *shortest*: every level before the one that reached `b` was read whole, and if an earlier level
  was cut the answer becomes `incomplete` with an empty path even when a longer route was seen.
- `detect_cycles(*, limit=MAX_CYCLES) -> dict` — declared dependency cycles, by iterative DFS
  (explicit stack, no recursion), reported as `mode: 'dfs-witness'`. Each cycle is rotated to start
  at its smallest id and reported once; a self-relation `a -> a` is a cycle of one. See *Cycle
  policy* for what the list does and does not claim.
- `cycle_findings(*, source='topology', now=None, window_seconds=60, limit=MAX_CYCLES) -> dict` —
  the same scan plus one canonical `coverage` event per cycle, built by
  `platform.detections.event` (imported for read-only use). See *Cycle policy* below.

Module-level observed plane:

- `inferred_relation_observation(source, *, observed_at, subject_id, target_id, relation, evidence,
  observation_id=None, subject_aliases=()) -> inventory.discovery.Observation` — build the observed
  record of an inference. `evidence` must be 1..`MAX_EVIDENCE_REFS` non-blank references of at most
  `MAX_EVIDENCE_CHARS` characters; a bare string is refused rather than split into characters.
  **Writes nothing.**
- `observed_edges(observations_path, source, *, history_limit=2, max_rows=None, skip_limit=20)
  -> dict` — read those records back through `discovery.history`. Newest claim per
  `(subject, relation, target)` wins; unusable claims — bad ids, a relation word outside the
  vocabulary, or an inference with no usable evidence behind it — are listed in `skipped` with
  `skipped_count` as the real total.

Types and constants callers use: `DeclaredEdge`, `ObservedEdge`, `TopologyRefusal` (a base
`InvalidInventory`, so an HTTP edge that already classifies inventory refusals classifies these),
`UndeclaredResource`, `DECLARED`/`OBSERVED`, `INFERRED_RELATION`/`INFERRED_TARGET`,
`CYCLE_RULE_PREFIX`, `RELATION_SHAPE`, `MAX_EVIDENCE_REFS`, `MAX_EVIDENCE_CHARS`.

## Direction, in one rule

An edge `src --relation--> dst` means **src depends on dst**, so `dst` is upstream of `src`.
`container --runs-on--> host` puts the host in `upstream(container)` and the container in
`impact(host)`. `shortest_path(a, b)` walks the same depends-on direction out of `a`, so a path
exists only if `a` transitively depends on `b`. This is v0.1's convention kept verbatim because
suppression (suppression), correlation (correlation) and rca (RCA) read the module docstring, not the code;
`test_the_direction_convention_is_written_in_the_module_docstring` pins the sentences and
`test_runs_on_makes_the_host_upstream_of_the_service` pins the meaning.

## Behavior worth knowing

**Where the edges are read from.** `inventory/index.py` exposes exactly one relation query,
`dependents()` (`index.py:133`) — impact-direction only, hard-coded to the
`('runs-on','depends-on')` types, node ids only, and no revision. It cannot answer a typed graph
question, so this module reads the same built index's `relations` table through the same public
read path the module already has: `index.readonly()` (the identical pattern
`presentation.resource_info` and `api.py`'s `/v1/inventory` already use). No new store, no new
file, no cache with its own staleness problem, and no edit to `index.py`.

**Source revision semantics.** A declared edge is meaningless without the declaration that
produced it, so `DeclaredEdge` carries `declaration_revision` (the operator's own label for the
declaration, whatever `index.build` was called with — a git SHA, a version, a filename: this module
never interprets it) and `declaration_sha256` (the canonical digest `index.build` computed). Both
come from `build_metadata` in the same index the edges come from, so an edge can never be quoted
against a revision that did not contain it. Every traversal result also carries the whole
`revision` dict at its top level.

**Observed timestamps and evidence.** An `ObservedEdge` carries `observed_at` (the snapshot's own
`observed_at`, the instant the source claimed it), `observation_source` (which producer saw it),
`snapshot_id` and its `evidence` references. It has **no** `declaration_revision` attribute at all
— not `None`, not an empty string — because "no declaration behind it" and "some declaration behind
it" are different answers. Conversely `DeclaredEdge` has no `observed_at`: a declaration is not a
measurement.

Evidence is what makes an inference checkable, so it is required at **both** ends of the boundary,
not only where it is convenient to ask. `inferred_relation_observation` refuses to build a claim
without it, and `observed_edges` refuses to return one: `observed.json` gives `evidence` no
`minItems` and `discovery.ingest` validates against the schema alone, so a hand-built document that
never passed through `discovery.snapshot` (the only writer-side refusal) can be sitting in the
observed database with `evidence: []`. That record is skipped visibly — reason `"carries an inferred
relation with no usable evidence reference behind it"` — never returned as an edge. The skip reasons
are fixed sentences and never quote the record, so an unbounded or credential-shaped attribute
cannot ride a read answer out of this module. Observations that carry no inferred relation at all
are not judged by this filter: a plain provider row with an empty evidence list is neither an edge
nor a skip. `test_an_evidence_free_inference_is_refused_on_the_read_boundary_too` walks the real
path (helper refusal → `ingest` accepts the hand-built document → `history` shows it → the read
skips it).

**Two planes, two calls.** `declared_edges()` reads the built index; `observed_edges()` reads the
observed database through `discovery.history`. No traversal (`upstream`, `impact`, `shortest_path`,
`edges_for`, `detect_cycles`) reads the observed plane at all, so an inference cannot silently
create an edge, shorten a path, or close a cycle. `test_declared_and_observed_edges_are_never_mixed`
and `test_the_declared_graph_ignores_an_inferred_cycle` are the proofs. Note that
`observed_edges()` does **not** resolve identity and does not require its endpoints to be declared —
resolution is `index.resolve`'s job and belongs to the worker; a read of the observed plane that
quietly dropped unresolvable claims would look like "nothing was seen".

**Bounds.** `depth` is hops (1 = direct neighbours) and must be `1..MAX_DEPTH` (32);
`max_rows` must be `1..ROW_CEILING` (1000) and defaults to `MAX_ROWS` (200); a neighbour query is
chunked at `FRONTIER_CHUNK` (200) ids; `shortest_path` is bounded in total work as well as per hop,
at `MAX_SEARCH_NODES` (2 000) discovered nodes and `MAX_SEARCH_ROWS` (5 000) rows read across the
whole search; `detect_cycles` loads at most `MAX_EDGES` (20 000) edges and **refuses** a bigger
graph rather than reporting a partial scan as complete; `limit` caps reported cycles at `MAX_CYCLES`
(100) and then sets `truncated`/`complete: False`; an inferred relation may carry at most
`MAX_EVIDENCE_REFS` (20) evidence references of `MAX_EVIDENCE_CHARS` (1 024) characters, which are
`observed.json`'s own numbers restated (that file is not this unit's to edit —
`test_the_evidence_bounds_are_the_ones_the_observed_schema_ships` fails if the two drift).
Out-of-range arguments are refusals, never clamps. Everything is deterministic: sorted frontiers,
`ORDER BY` on every query, results sorted by `(depth, resource_id)`.

**Three bounds, three names.** Every traversal carries `truncated` and, beside it, `truncated_by`:
the sorted list of which bound actually cut the answer — `'depth'`, `'rows'` (a hop's rows, or the
reached-node budget) or `'nodes'` (`shortest_path`'s total discovered nodes). The distinction is not
cosmetic: a caller such as the incident label must say "there were more names for this cell" on a
row cut and say nothing on a depth cut, because one hop is what the view asked for rather than what
the graph has.

A **depth** cut is reported only when the next hop would have reached something this call had not
already reported. That is decided by one bounded existence check (`_has_unexplored`: a
`SELECT 1 … LIMIT 1` per frontier chunk, which walks nothing), so the two honest cases stay apart:

| the graph | the call | reported |
|---|---|---|
| `a -> b -> c` (built) | `upstream(a, 1)` | `nodes: [b]`, `truncated: True`, `truncated_by: ['depth']` — `c` is missing |
| `a -> b -> c` | `upstream(b, 1)` | `nodes: [c]`, `truncated: False` — `c` is a leaf sitting exactly on the boundary |
| `top -> mid -> leaf -> mid` | `upstream(top, 2)` | both nodes, `truncated: False` — the boundary frontier leads only to nodes already reported |
| a cycle `a ⇄ b` | `upstream(a, 8)` | `[b]`, `truncated: False` — the loop is not "work remaining" |
| `fan-top -> 6 leaves`, each `-> tail` | `upstream(fan-top, 1, max_rows=3)` | `truncated_by: ['depth', 'rows']` — both bounds bit |

The check degrades safe: if the exclusion set could not be bound as query parameters
(`SQL_PARAMETER_BOUND`), the answer is "work may remain" and the result is truncated, never
complete. And `shortest_path` accumulates its marks over the whole search instead of overwriting
them per level, so a hop whose rows ran out can never be answered as `absent` three hops later
because a later frontier happened to be empty. `test_a_cut_chain_is_reported_as_cut_in_both_directions`,
`test_a_leaf_exactly_on_the_depth_boundary_is_not_reported_as_work_remaining`,
`test_a_row_cut_in_one_hop_is_not_an_absence_when_the_next_frontier_closes` and
`test_a_row_cut_may_not_be_answered_by_a_longer_path_found_later` are the pins.

**Refusals, so an empty answer means something.** An undeclared resource id raises
`UndeclaredResource` from every entry point — it is never an empty neighbourhood. A declared leaf
genuinely returns `nodes: []` with `truncated: False`, which is why the empty case is trustworthy.
`complete` on `detect_cycles`/`shortest_path` distinguishes "the whole graph was searched" from
"the bound stopped me", and `truncated_by` names the bound.

**Cycle policy — the measured case.** The builder's gatekeeper is
`inventory/index.py:47` — `build()` calls `validation.declared(document)` before it writes a row —
and that function refuses a relation whose **target** is not declared
(`inventory/validation.py:123`, `'Relation target is not declared'`). It says
nothing about cycles. Measured on 2026-09-08 with the fixture in
`CycleTests.test_the_builder_admits_a_declared_cycle`: a two-resource declaration whose relations
point at each other **builds**, indexes and passes `PRAGMA integrity_check`. So cycles are
*admitted*, the gatekeeper does not catch them, and this unit's coverage is the check that does:
`detect_cycles()` reports them, and `cycle_findings()` turns each into a `coverage` event with
`rule_id = topology.declared-cycle.<first 16 hex of the cycle digest>` anchored on the cycle's
smallest node id. No root is silently chosen and no traversal breaks on a loop — every walk carries
a visited-set guard.

**What the cycle scan may claim, and what it may not.** `detect_cycles` reports **DFS witnesses**
(`mode: 'dfs-witness'`), and the two halves of that sentence have different strength:

- *Absence is proved.* `cycles: []` with `complete: True` means the declared graph is acyclic. A
  DFS that colours every node and every edge of the index without finding a back-edge onto the
  current path cannot exist on a graph that has a cycle — so the empty verdict is sound, and
  `test_an_empty_complete_scan_is_a_proof_of_acyclicity_not_a_shrug` pins it on a diamond.
- *Presence is witnessed, not counted.* A non-empty list holds cycles that really exist, one per
  back-edge of **this** DFS forest. The graph may hold further elementary cycles that the traversal
  never walks, because whichever edge reaches a white node first becomes a tree edge: `w-a -> w-b
  -> w-c -> w-a` plus `w-a -> w-c` contains both `w-a ⇄ w-c` and the three-node loop, and the
  complete scan reports only the latter. `test_a_dfs_witness_list_is_not_an_enumeration_of_every_cycle`
  pins that, so nobody has to rediscover it while reading `count` as a census.

So `count` is never "the number of cycles in the declaration", a clean `status` is stronger than a
`finding` one, and neither number is "every cycle". Loading all `MAX_EDGES` edges is what makes the
absence claim sound; it is not what makes a witness list exhaustive, and no bound can do that.
`truncated` is the third case: past `limit` the scan stops early and stops colouring, so neither the
verdict nor the list survives — `complete: False`, and `cycle_findings()` posts only the first
`limit` events.

**What a cycle event can and cannot say.** `state.validate_event` admits ten evidence parameter
names with 256-character string values, so the full node list cannot ride the event. The event
carries the anchor `resource_id`, the cycle identity in the rule id, and
`artifact_sha256 = declaration_sha256` — a reference a reviewer can re-check against the served
index. No evidence *sample* is posted, so `Store.get_evidence` answers `unavailable` for it, exactly
as the drift producer's does. Re-derive membership with `detect_cycles()` against the index whose
`declaration_sha256` the evidence names.

## Operator surface

One labelled section, on the incident view only: `presentation.dependency_info()` is called from
`presentation.records()` for `table == 'incidents'` and adds `upstream_name` ("what this resource
depends on") and `downstream_name` ("what depends on it") to each row's `display`, at depth 1 and
five names, reached through `Topology.upstream`/`Topology.impact`. The ways an answer can be
empty are five sentences: `Topology not configured` (no index is mounted), `No resource on this
incident` (a platform-level incident names nothing), `Not declared` (the index does not know that
UUID), `Topology unavailable` (the index could not be read), and `Nothing declared above it`/
`Nothing declared below it` (declared, with nothing on that side). A cut list says `(more; this
list is bounded)` — and only a **row** cut says it: this view asks for one hop, so a depth cut is
what the operator requested, not a shortened list (`test_only_a_row_cut_marks_the_name_list_as_bounded`).

### The measured reach of `inventory/api.py`

The allowlist offered `local_observe/inventory/api.py`; **no route was added there.** What that
surface actually is was measured (in-process ASGI, `datasette` 0.65.3 + `datasette-graphql` 2.2 as
the component lock pins, an index built by `index.build`, no network): `protect()` is a single
ASGI wrapper that authenticates, then hands *all* routing to Datasette, so the reachable surface is
whatever Datasette itself defines, over the built index (whose database name is the file stem,
`inventory` in the shipped compose):

| reachable with the reader credential | refused |
|---|---|
| `/`, `/-/databases`, `/-/versions`, `/-/settings`, `/-/plugins` (200, server metadata) | unauthenticated anything → 401; `POST`/any non-`GET`/`HEAD`/`OPTION` → 405; websocket → close 1008 |
| `/inventory`, `/inventory.json`, `/inventory/<table>.json` and `.csv` for `resources`, `relations`, `build_metadata` (bounded: `default_page_size` 50, `max_returned_rows` 100, `_size` > 100 → 400) | arbitrary SQL → 403 (`?sql=` on a table or database page), `/inventory/-/sql` → 400 |
| `/graphql/inventory?query=…` — and it answers a relation query with **both endpoints resolved** (`source_id { id name }`), i.e. one labelled hop, in one call | full-table export → `?_stream=on&size=max` → 400; `allow_download` off; `graphiql`/`/-/graphql-explorer` → 404 (not enabled by these settings) |

What is **not** on it: any traversal. No route answers `upstream`, `impact`, `shortest_path`,
`edges_for` or a cycle verdict; the closest thing is the raw `relations` table and GraphQL's one-hop
joins, from which a client would have to rebuild the traversal — unbounded, with no `truncated`,
no depth semantics and no guarantee the planes stayed apart. That is the honest reason the module
was not "put behind `inventory/api.py`": the endpoint would be a new authenticated graph surface
with its own bounds and role, and the read model already has an in-process consumer per brief that
needs it (suppression, correlation, rca) plus one operator surface that is genuinely reachable today (the
incident view). Auth tests that exist: `tests/test_inventory_api.py` (5 tests — bearer and basic
accepted, ambiguous/malformed headers refused, a token under 24 characters refused at `protect`,
`POST`/unauthenticated/websocket never reaching the wrapped app, and the compose read boundary).
They test `authenticate`/`protect` in isolation; **nothing in `tests/` imports `datasette`** (it is
not in `requirements-test-base.txt`, so an isolated base tier could not run such a test), which
means the route table above is *not* pinned by this repository's suite: the only place the real
Datasette answers is `scripts/conformance_inventory_stage.py` (REST row count, GraphQL query, 401 /
403 / 405 denials) on the staging daemon, which is a reviewer/owner run, not a test. Missing
integrations, named plainly: no topology route, no per-route authorisation beyond the single
reader token (every Datasette route is equally readable to anyone holding it), no test that the
settings above (`default_allow_sql`, `allow_download`, `allow_csv_stream`, the row and time limits)
are actually applied — only the staging probe that checks three of their effects.

**Not wired, and said plainly:**

- Nothing posts a `coverage` event: `cycle_findings()` returns event dicts and **no caller submits
  them**. Intake is `event intake`'s, the detector loop is `alert conditions`'s, and this brief owns neither, so a
  declared cycle is currently only visible to a process that imports this module and asks.
- No HTTP endpoint was added. See the measured table above: `inventory/api.py` reaches Datasette
  and GraphQL, and the incident view is the only operator surface this unit touches. Consumers
  import this module (it is one process, one file).
- The Homepage tiles and `/v1/overview` do not show topology; `overview.py` is not this unit's.
- The MCP tools do not expose graph queries; that surface is `mcp tool surface`'s.

## Gotchas / debt

- **`truncated_by` is a vocabulary, not a debug field.** `'depth'`, `'rows'` and `'nodes'` are what
  `presentation.dependency_info` branches on (only `'rows'` marks a name list as bounded) and what
  later consumers will key on. Adding a fourth mark is a contract change for every caller that
  treats `truncated: True` as "re-ask with a bigger bound", because `'depth'` is the one mark a
  larger `max_rows` cannot fix.
- **A complete depth answer costs one extra query.** `_has_unexplored` runs only when a walk stops
  on its hop bound with a frontier still open, and it binds every already-reported id as a
  parameter (bounded by `ROW_CEILING`, chunked by `FRONTIER_CHUNK`). Its `SQL_PARAMETER_BOUND`
  guard has never been reached in tests — hitting it means a `ROW_CEILING` increase that must move
  this constant with it — and the degrade-safe branch (`"work may remain"`) is pinned by
  `test_an_existence_check_that_cannot_run_says_work_may_remain`, which shrinks the ceiling to
  prove the direction of the lie.
- **`shortest_path` may return `found` on a hop whose rows were cut** (see
  `test_a_cut_at_the_level_that_reached_the_target_still_proves_shortest`): a cut at the level that
  reached the target can hide other paths of the same length, never a shorter one. That is
  deliberate, but it means `status: 'found'` with `truncated: True` is a real combination — the
  length is proved, the tie-break was made over a partial neighbour set.
- **`MAX_SEARCH_NODES`/`MAX_SEARCH_ROWS` are per-call budgets, not a fairness queue.** Two
  concurrent graph questions on a wide index can each read up to `MAX_SEARCH_ROWS` rows; there is
  no shared work meter across calls and no cache to make a second one cheaper.
- **N+1 on the incident page.** `records()` opens the index once per row inside `resource_info` and
  twice more here (once for each direction). An incident page is bounded at 100 rows, so this is
  ~300 read-only opens; a batched reader would need either a multi-resource traversal or a
  connection that outlives one call. Deliberately not paid for here.
- **Two depth-1 hops, not a transitive answer.** The incident label shows direct neighbours only.
  That is a presentation choice (`TOPOLOGY_DEPTH`, `TOPOLOGY_NAMES`); the transitive view is the
  API's job and needs a real surface, not a longer string in a table cell.
- **`presentation.text()` caps each name at 160 characters** and does not mark the cut, the same
  behaviour every other label in that module has.
- **The relation vocabulary is duplicated.** `RELATION_SHAPE` restates
  `inventory/schemas/declared.json`'s `relations.items.type` pattern because that file is
  `discovery providers`/`module contract`'s, not this brief's. `test_the_pattern_matches_the_shipped_declaration_schema`
  fails if the two drift; widening the vocabulary in the schema must move that test and this
  constant together.
- **`detections` is imported inside `cycle_findings()`** to keep `import local_observe.topology`
  free of the platform's SQLite/state import layer (a store-side consumer would otherwise drag the
  platform in). It is also the one place this inventory-side read model reaches "up" into
  `platform`; if a later wave objects, the event construction is the thing to move, not the graph.
- **No resolution half of a cycle finding.** This unit holds no state, so a cycle that leaves the
  declaration stops being reported rather than opening a `resolved` event; the condition's own
  ageing (`state.py`, `suppression`/`correlation`) is what closes it. Do not add a cursor here — the module is
  stateless by design.
- **v0.1's network collectors are not ported** (LLDP/CDP/ARP/traceroute, `legacy:topology/collectors/
  network.py`): private-LAN shaped, and this product holds no prober. `sweep_provider.py` is the
  only thing here that ever names an address range, and it is a discovery source, not an edge
  writer. An inferred edge reaches this module only as an observation someone else ingested.
- **Observed edges are only as good as their source's `complete` claim**, which
  `observed_edges()` does not re-check: it reports what the snapshots say. A caller that wants
  "the source could not see anything" must read `discovery.latest`/`ageing` alongside it.

## Running its tests

```
python -B -m unittest tests.test_topology tests.test_topology_observed
```

From the repository root, on the base tier (stdlib + PyYAML + jsonschema; no optional
dependency is imported by this module or either test).

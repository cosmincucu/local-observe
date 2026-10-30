# Resources, queries, rules and configuration over HTTP

This page covers the route family in `local_observe/platform/resources_api.py`: the reads that answer
"what is declared, what was seen, and how far apart those two are", the previews that answer "what would
this rule decide, and what would this configuration become", and the refusals that keep both honest.

Three properties hold across every route here, and each one exists because the alternative produced a wrong
answer in review:

* **Declared and observed are separate planes.** An answer says which plane it describes (`plane`) and never
  blends a declaration with an observation into one row. Where the two are compared, the answer carries both
  values side by side rather than a reconciled one.
* **A missing artifact is a stated condition, not an empty list.** A read whose input is not mounted answers
  `200` with `status: unavailable`, `complete: false` and a sentence naming the variable to mount. It never
  answers `[]`, because "I have nothing to read from" and "there is nothing" are different claims about the
  estate. A *write* that would have to put something on disk answers `503 operation_unavailable` instead of
  pretending to succeed.
* **Nothing here runs anything.** Rule routes are dry runs of the same evaluator a producer round uses, and
  configuration routes are document-in, artifact-out previews. No event is filed, no cursor moves, no file is
  written, no daemon is contacted, and every such answer says so in `durable: false` / `written: false` /
  `deploy_authorized: false` and lists what it did not do in `not_performed`.

| Question this page answers | Section |
| --- | --- |
| What has to be mounted, and what happens if it is not? | [Prerequisites](#prerequisites), [Reads with nothing to read](#reads-with-nothing-to-read) |
| What can I call, with which credential, with which parameters? | [Routes](#routes), [Bounds](#bounds) |
| Why does this answer not merge the two planes? | [The two planes](#the-two-planes) |
| What did a rule decide, and what did it *not* do? | [Previews](#previews) |
| Which error answers which mistake? | [Errors](#errors) |
| Which of these commands have no route, and why? | [Refused by decision](#refused-by-decision) |

## Prerequisites

The routes read files that other parts of the product build. Nothing here builds them over HTTP — a bearer
that could rebuild the served index could replace it with anything — so the mounts are the whole bootstrap.

| Mount | Set by | If unset or absent |
| --- | --- | --- |
| `LO_INDEX_PATH` | `lo-inventory build` (the CLI writes the SQLite index and points the service at it) | declared reads answer `unavailable`; declared writes answer `503` |
| `LO_OBSERVED_PATH` | the first `POST /v1/observed-snapshots`, or `lo-inventory discover` writing directly | observed reads answer `unavailable`; the ingest, proposal and drift paths answer `503` |
| `LO_PROPOSALS_PATH` | the operator, as a writable directory | `POST /v1/resource-proposals` answers `503`; reads of a draft answer `unavailable` |
| `LO_CLICKHOUSE_URL`, `LO_CLICKHOUSE_READ_USER`, `LO_CLICKHOUSE_READ_PASSWORD` | a deployment that has an analysis reader | `/v1/queries/signals` and `/v1/queries/topology` answer `unavailable`; `GET /v1/capabilities` reports `telemetry_reader: false` |

Two details that are easy to get wrong from the outside:

* **`LO_OBSERVED_PATH` set but no file yet is a different answer from unset.** The first case says "a
  producer has to file a snapshot first"; the second says "nothing is mounted here". `GET /v1/capabilities`
  reports both in `artifacts.observed_dataset`, because a caller that guessed wrong would debug the wrong
  half of the deployment.
* **The reader variables are read once at boot** by `local_observe.platform.query.open_reader`, which never
  raises and never falls back to a legacy password variable: a producer that starts without a query path
  still serves everything else.
* **For the two artifact mounts, blank is not unset.** `LO_OBSERVED_PATH=` in a generated environment file
  refuses the boot, naming the variable and never its value: a line somebody wrote is an intention, and
  quietly serving `unavailable` forever would hide the deployment error. Unset means "this install runs no
  observed plane" and boots fine. (`LO_OVERVIEW_PATH` and the channel variables take the opposite convention,
  where blank means unset — the difference is that those are read by code this family did not write.)

`GET /v1/capabilities` is the one read that settles "is that missing feature a bug, a mount, or a decision?"
It enumerates this family's operations as `supported` or `unavailable` with the reason, and lists the
`excluded` ones in `declines` with the command that does the job instead. Its scope is **this process**: a
producer running in another container with its own mounts is invisible from here.

## Routes

| Route | Roles | Census row | What it answers |
| --- | --- | --- | --- |
| `GET /v1/resources` | `reader`, `proposer`, `human`, `executor` | `resource.read` | Declared resources, filtered by `kind`/`name`, paged |
| `GET /v1/resources/resolve` | same four | `resource.alias.resolve` | Which declared resource one alias names (`resolved`, `unknown`, `unknown_uuid`) |
| `GET /v1/resources/{id}/dependents` | same four | `resource.dependents.read` | What declares it depends on this, and what depends on it |
| `POST /v1/resource-declarations/validation` | same four | `resource.declaration.validate` | Whether one declaration document is valid, with the validator's sentence |
| `GET /v1/observed-snapshots` | same four | `resource.observation.history.read` | Snapshots a source filed, newest first, summaries only |
| `POST /v1/observed-snapshots` | `producer` | `resource.observation.record` | File one discovery snapshot (`inserted` or `duplicate`) |
| `GET /v1/observed-snapshots/drift` | the four readers | `resource.drift.evaluate` | Declared against observed, source by source, with each source's coverage |
| `POST /v1/resource-proposals` | `proposer` | `resource.proposal.build` | Draft the declaration for one observed-but-undeclared resource |
| `GET /v1/resource-proposals/{id}` | the four readers | `resource.proposal.read` | One drafted proposal, `published: false`, `declared: false` |
| `GET /v1/queries/signals` | the four readers | `resource.query.series` | One bounded metric/log/trace series from the analysis reader |
| `GET /v1/queries/topology` | the four readers | `resource.query.topology` | A bounded dependency walk in one direction |
| `GET /v1/capabilities` | the four readers | `resource.capability.read` | What this process can answer, what waits on a mount, what is refused |
| `POST /v1/rules/validation` | `producer`, `proposer` | `rule.validate` | Whether one rule document of a named family builds and validates |
| `POST /v1/rules/detections/evaluations` | `producer` | `rule.detection.evaluate` | What one detection rule decides over a supplied sample |
| `POST /v1/rules/sustained/evaluations` | `producer` | `rule.sustained.evaluate` | The same for a sustained-condition rule |
| `POST /v1/rules/config-drift/comparisons` | `producer` | `rule.config_drift.evaluate` | The same for a watched-file comparison |
| `POST /v1/rules/pathcheck/evaluations` | `producer` | `rule.pathcheck.evaluate` | The same for reachability observations |
| `POST /v1/rules/slo/evaluations` | `producer` | `rule.slo.evaluate` | The same for an objective over supplied points |
| `POST /v1/rules/forecast/evaluations` | `producer` | `rule.forecast.evaluate` | The same for a forecast rule |
| `POST /v1/deployment/locks` | `proposer`, `human` | `config.deployment.lock` | The lock a set of package documents resolves to |
| `POST /v1/deployment/plans` | `proposer`, `human` | `config.deployment.plan` | The diff-and-authority plan between three rendered states |
| `POST /v1/deployment/renderings` | `proposer`, `human` | `config.deployment.render` | The file map a render would write |
| `POST /v1/deployment/dashboard-exports` | `proposer`, `human` | `config.dashboard.export` | The review document for one dashboard edit |

`GET /v1/inventory` (`resource.inventory.read`) stays exactly as it was: the same shape, the same
`display` projection, the same bounds. `/v1/resources` is the newer bounded/paged declared read beside it,
not a replacement, and the two disagree on nothing because both read the same index rows.

Reads with an `{id}` in the path take a declared UUID; an identifier that is not a UUID, or a UUID no
declaration names, is `404 not_found` — that is the fact a caller came for, and it is not an error in the
sense of a broken request. Role sets are written once, in `x-required-role` in
[`openapi.yaml`](openapi.yaml). A `summary` credential is refused by the dispatcher before a single body byte
is read, so that row cannot be a parser or size verdict wearing a 403; every other role is checked by the
route as it starts, before an artifact is opened, so a wrong-role call cannot cost an index read or leave a
file behind.

## The two planes

`GET /v1/observed-snapshots/drift` is the route where mixing is tempting, so it is the one spelled out:

* The **index** is the declaration half: what an operator said exists.
* The **observed dataset** is the observation half: what a probe said it found, at a time, in a window.
* A finding names one resource and carries `declared` and `observed` values separately (`differences`), or
  the resolution that failed (`resolution.status: conflict` with both candidates). There is no field that
  says which one "won", because nothing here decides that.

`sources` grades each named source `whole`, `source_stale`, `source_unavailable` or `coverage_incomplete`.
That last grade is what a source that claimed no completeness earns: a snapshot with `complete: false` may
have found only part of what exists, so an empty `rows` list from it must not print as "no drift". A source
that failed outright (`status: error`, no observations) keeps its error code and grades `source_unavailable`;
its silence is never counted as clean.

Inferred relations are the same story: they live in the observed dataset and are read back as
`topology.observed_edges`, which `GET /v1/resources/{id}/dependents` deliberately does not merge into the
declared graph. An inference is an inference.

## Reads with nothing to read

A read that cannot reach its artifact answers `200`, not an error:

```json
{"schema_version": 1, "status": "unavailable", "complete": false, "rows": [], "limit": 50,
 "returned": 0, "truncated": false,
 "reason": "No built inventory index is mounted in this process (LO_INDEX_PATH); nothing here rebuilds it — lo-inventory build does",
 "provenance": {"plane": "declared", "source": "built inventory index", "mounted": false,
                "declaration_revision": null, "declaration_sha256": null, "built_at": null,
                "index_schema": null, "unavailable": "…same sentence…"}}
```

`rows: []` there is bounded by `complete: false` — the reason is why the list is empty, and a caller that
ignores `complete` is choosing to print "nothing" about a mount it can list with
`GET /v1/capabilities`. A write that would have to create or replace a durable artifact answers
`503 operation_unavailable` with that same sentence, because a `200` would claim a state change that did not
happen. Which is also why the reads that need a named selector still refuse a request that omits it: a
history read with no `source` is a `400` ("A snapshot history read names its source"), never an empty list
about every source at once.

## Previews

Every rule route calls the same function its producer round calls (`detections.evaluate`,
`conditions.evaluate`, `configdrift.compare` + `drift_finding`, `pathcheck.classify` + `verdict_findings`,
`alerts.evaluate`, `timetothreshold.evaluate`) and returns what that function returned, plus the boundary's
own statements:

* `durable: false`, `not_performed: ["filed an event", "advanced a cursor", ...]`, and no read or write of
  any cursor table. Two callers can run the same preview at once and neither sees the other's state.
* Every `POST` here is inside the guarded set (`resources_api.writes`), which buys two things and costs a
  stored answer: a body may not name an actor (`api_contract.assert_no_actor_claim` runs first, so
  `{"actor": ...}` is refused rather than preferred), and a retry with the same `Idempotency-Key` and body
  replays the first answer instead of evaluating twice. A preview is worth replaying for exactly that
  reason: the caller is asking what the same inputs decide, and a second run that disagrees is a bug.
* `judged` is the evaluator's own verdict count: `true` only when at least one non-`coverage` event came
  back. Coverage-only means the rule could not judge the watched thing, and `judged: false` says so rather
  than letting a caller read two `coverage` rows as "healthy".
* Events are returned as event-shaped objects with the **credential's** identity in `actor`. Body fields
  never name an actor; `api_contract.ACTOR_CLAIM_FIELDS` is refused before parsing.
* `sample`/`points`/`observations` are the caller's evidence, so the caller owns staleness: the evaluators
  refuse samples newer than the window they align to, and a window older than the rule's
  `max_age_seconds` grades as coverage, not as health.
* `POST /v1/rules/validation` is the door's validator only: it answers whether the document *builds* a rule
  of the named family. It does not prove a producer would accept it, and it does not compile Sigma (see
  [Refused by decision](#refused-by-decision)).

The four configuration routes are the same bargain in the other direction: the caller supplies the documents
(packages, lock, deployment, or three rendered states) and receives the artifact the pure
`deployment.content` functions produce. No registry fetch, no trust verification, no Docker daemon, no
deployment authority — a `200` from `POST /v1/deployment/plans` includes `deploy_authorized: false` even when
the plan is clean, because authorization is a human act recorded elsewhere.

## Bounds

Refused, never clamped: a caller that asks for `limit=201` gets `400`, not a quiet 200.

| Bound | Value | Why that number |
| --- | --- | --- |
| Page size (`/v1/resources`, dependents) | default 50, max 200 | `api_contract.PAGE_LIMIT_*`, shared with every other bounded read |
| Query bytes | 512 | `api_contract.MAX_QUERY_BYTES`, checked before parsing |
| History page | default 10, max 20 | `discovery.history` parses every payload whole and one snapshot may hold 10 000 observations, so the bound is on what one request may cost |
| Drift sources | 8 | one read's wall time and one answer's size, both visible in `sources` |
| Observed freshness | 1 … 604 800 s | a week is the longest window whose "stale" verdict still means something to an operator |
| Topology depth / rows | 1–4, max 200 rows | `topology.MAX_DEPTH`/`MAX_ROWS` are the walk's own ceilings; these are what this surface exposes, matching the MCP tool declaration |
| Series window | 1 … 10 080 minutes | `tools.SERIES_WINDOW_MINUTES`, the same span the MCP read allows |
| Rule sample points | 2 000 | `conditions.MAX_POINTS` |
| Pathcheck observations | 1..64 probes | `pathcheck.MAX_PROBES` — one window's worth of probes; the expected-target and expected-vantage lists are bounded by the classifier's own 32-entry ceiling, which is what its coverage math costs |

Every list answer carries `limit`, `returned`, `truncated` and `complete`. `/v1/resources` carries a cursor
that also holds the declaration digest it paged over, so a page request against a rebuilt index is refused
instead of silently skipping or repeating rows.

## Errors

| Code | Status | What the caller did |
| --- | --- | --- |
| `invalid_request` | 400 | an unknown query parameter, a repeated one, a non-decimal `limit`, a value outside a bound, an alias type outside the inventory vocabulary, a body field naming an actor, or a JSON body that is not an object |
| `invalid_pagination` | 400 | a cursor this service never issued, or one whose declaration digest no longer matches the mounted index |
| `unauthorized` / `forbidden` | 401 / 403 | no credential or wrong role; `producer`-only writes refuse everyone else before their body is read |
| `not_found` | 404 | a non-UUID or undeclared `{id}`, an unknown proposal id, an undeclared topology root |
| `conflict` | 409 | an observed snapshot replayed under an id that already holds different evidence, or a second snapshot at the same source timestamp: the row a source filed is evidence, not a mutable cache. Also the answer when an `Idempotency-Key` was already spent on a different body |
| `body_too_large` | 413 | the dispatcher's budget, stated once for the whole surface |
| `operation_unavailable` | 503 | the durable artifact this write needs is not mounted. Message names the variable; nothing is queued and nothing is half-written |
| `internal_error` | 500 | a defect. `request_id` correlates it to one server-side log line |

Domain refusals travel as `400` with the domain's own sentence, not as invented codes: an unresolvable
observation for a proposal, a rule document that will not build, a source whose newest snapshot is stale.

## Refused by decision

Nine census rows in this area are `excluded`. They are not gaps; each is a route this build would be wrong
to serve. `GET /v1/capabilities` returns them as `declines`, so the refusal is discoverable rather than
something a caller deduces from a `404`:

| Row | Why no route |
| --- | --- |
| `resource.index.build` | Rebuilding the served index over HTTP would let any bearer replace the input every other read here depends on. It is `lo-inventory build`. |
| `resource.discovery.docker` | Takes a caller-named Docker daemon socket. Serving it is backend proxying: the socket is the credential, and it is not the caller's to point at. |
| `resource.proposal.publish` | Pushes a branch and opens review. That is a human decision with a human identity behind it. |
| `resource.inventory.mcp` | The MCP surface and this one read the same declared index; two contracts for one answer drift apart. |
| `resource.dataset.read` | Third-party Datasette/SQL surface. Fronting it means fronting arbitrary queries over the observed dataset. |
| `rule.sigma.compile` | Its output is executable SQL. It belongs to the pinned compiler tier, which runs it in a sandbox and refuses unprovenance'd input. |
| `config.deployment.export` | `export-storage`, `export-signoz` and `export-homepage` need a Docker daemon, subprocesses, or token-backed endpoints. `export_dashboard` is pure and *is* served, as `POST /v1/deployment/dashboard-exports`. |
| `administration.anomaly.migrate` | Offline state migration and recovery. Needs the store that must not be serving while it runs. |
| `administration.component.serve_inventory` | The long-lived server process itself. A route cannot start the thing that answers it. |

The general rule is on the [COVERAGE page](COVERAGE.md): anything that is a long-lived process, an offline
bootstrap or recovery step, an arbitrary query or shell or backend proxy, or a claim a human must approve,
stays a command.

## Testing

`tests/test_api_resources.py` exercises this family against a real built index, a real observed dataset and
the real `deployment.content` examples — not mocks — and asserts the properties above rather than string
snapshots: each route answers without its mount, each refuses the wrong role before parsing, each read keeps
its plane, each preview leaves no state behind, and every answer body validates against the schema
`openapi.yaml` claims for it.

`tests/test_api_openapi_conformance.py` then checks the census, the document and the served route literals
against each other three ways, including that every templated path in the document is reachable with a
concrete id. A route added here without a census row and a documented schema fails that pair of files, not a
review comment.

## Limitations

* **No subscription, no stream.** Every read is one answer about one moment; `ETag`/revalidation is not
  wired on these routes, so "watch this" is polling with a cursor, and the window semantics of `/v1/records`
  still answer the durable plane.
* **One process.** Capability and mount answers describe this service only. Producers, their cursors and
  their rule documents are a deployment fact, recorded in the overlay, not here.
* **Previews cannot prove a producer agrees.** `POST /v1/rules/validation` checks the document against the
  builder every round already uses; it cannot know a producer's own configuration, its window grid or its
  source bindings. The durable answer stays in the event the producer files.
* **No write path for declarations.** The declared plane changes through `lo-inventory build` and review, and
  the only HTTP write in this family that reaches disk is an observed snapshot from its own source.

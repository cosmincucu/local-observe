"""The resources, queries, rules and configuration route family.

`platform/api.py` owns the request boundary — credential to actor, one request per connection, body
limits, the idempotency claim, the answer envelope. This module owns the paths that answer "what is
declared, what was seen, what would a rule say, and what would a configuration change do", and nothing
else. It opens no operational table, mints no identity, and refuses nothing that the inventory,
topology, discovery, rule or deployment modules have not already refused: a route is those same rules
seen from one URL, which is why every branch below calls the function the CLI calls.

Four claims hold for every route here, and each is a judgement rather than a formality:

* **Declared and observed are never merged.** A declaration answers "what the operator says is meant to
  exist"; an observation answers "what a source saw, at an instant, with this evidence".
  `/v1/resources*` reads the first, `/v1/observed-snapshots*` the second, and
  `/v1/observed-snapshots/drift` reports the difference as findings without editing either. `plane` is a
  field of every answer here, so a caller cannot flatten the two by accident.
* **A bound is stated, not hidden.** Every list carries `limit`, `returned`, `truncated` and `complete`.
  `complete: false` means "this answer is not the whole answer" — set for a page that stopped at a bound,
  a source that reported nothing, and a backend this installation never mounted. A short list never reads
  as an empty estate (`docs/CONTRACTS.md` §2).
* **An unavailable artifact is an answer, not a crash and not an empty success.** A read whose store is not
  mounted answers `200` with `status: "unavailable"`, the sentence naming the variable that mounts it, and
  `complete: false`; `GET /v1/capabilities` says which routes are in that state before anyone calls them.
  A *write* — the one thing here that records a fact — answers `503` instead, because a `200` that recorded
  nothing would be the exact lie this family exists to avoid.
* **Nothing here pages, deploys, publishes or files an event.** The rule routes build a rule with that
  family's own builder and report the verdict, the events it *would* file, and `durable: false`; the
  configuration routes return the rendered artifact with `written: false` and `deploy_authorized: false`.
  The producer loops, the discovery sweep, the content bundle and the outbound proposal stay on the CLI,
  where their cursors and their paths live — and the census row for each says so.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import urllib.parse
from collections.abc import Mapping, Sequence
from typing import Any

from local_observe import topology
from local_observe.deployment import content as deployment_content
from local_observe.forecast import timetothreshold
from local_observe.inventory import discovery, index, validation
from local_observe.inventory.validation import InvalidInventory, digest, utc_text
from local_observe.slo import alerts
from . import api_contract, conditions, configdrift, detections, pathcheck
from .state import Actor, StateError, clock, identifier, label, require

# -------------------------------------------------------------------------------------- route literals

#: The collection route over the built index. Deliberately distinct from `/v1/inventory`, which is the
#: older projection the portal renders (100 rows, display labels, no paging) and which stays byte for byte
#: what installed callers assert. This one is bounded, paged, filterable, and says which bound applied.
RESOURCE_ROUTE = '/v1/resources'
#: The alias/identity read. It is a *sibling* of `/v1/resources/{id}`, so it is matched as a literal
#: before any identifier is read out of a path — and no resource is ever named `resolve`, because an id
#: on this family is a canonical UUID.
RESOLVE_ROUTE = '/v1/resources/resolve'
#: Sub-path prefix of the dependents read (`/v1/resources/{id}/dependents`).
RESOURCE_CHILD_PREFIX = '/v1/resources/'
#: The draft-declaration check. A validation is a `POST` because it carries a document, not because it
#: writes: the answer is a verdict with `recorded: false`, and nothing on disk changes.
DECLARATION_VALIDATION_ROUTE = '/v1/resource-declarations/validation'
#: The observed plane: snapshots in, bounded history, and the drift comparison out.
OBSERVED_ROUTE = '/v1/observed-snapshots'
DRIFT_ROUTE = '/v1/observed-snapshots/drift'
#: The proposal surface: draft one declaration proposal from one undeclared observation, and read back a
#: drafted one. Publishing to a repository is not here — see `resource.proposal.publish`.
PROPOSAL_ROUTE = '/v1/resource-proposals'
PROPOSAL_CHILD_PREFIX = '/v1/resource-proposals/'
#: The two query reads: the HTTP shape of what `signal_series` and `topology_neighbourhood` are to an MCP
#: agent. One signal table and one walk behind both surfaces, so they cannot drift apart.
SIGNAL_ROUTE = '/v1/queries/signals'
TOPOLOGY_ROUTE = '/v1/queries/topology'
#: What this installation can reach, operation by operation.
CAPABILITY_ROUTE = '/v1/capabilities'
#: The rule lifecycle. Validation and evaluation are separate paths because they answer different
#: questions — "is this rule well built" and "what would it say about this fixture".
RULE_VALIDATION_ROUTE = '/v1/rules/validation'
DETECTION_EVALUATION_ROUTE = '/v1/rules/detections/evaluations'
SUSTAINED_EVALUATION_ROUTE = '/v1/rules/sustained/evaluations'
CONFIG_DRIFT_COMPARISON_ROUTE = '/v1/rules/config-drift/comparisons'
PATHCHECK_EVALUATION_ROUTE = '/v1/rules/pathcheck/evaluations'
SLO_EVALUATION_ROUTE = '/v1/rules/slo/evaluations'
FORECAST_EVALUATION_ROUTE = '/v1/rules/forecast/evaluations'
#: The configuration surface. Each one is a pure function over documents the caller already holds; none
#: touches a working tree, fetches a package, or deploys anything.
LOCK_ROUTE = '/v1/deployment/locks'
PLAN_ROUTE = '/v1/deployment/plans'
RENDER_ROUTE = '/v1/deployment/renderings'
DASHBOARD_EXPORT_ROUTE = '/v1/deployment/dashboard-exports'

#: The exact literals this family answers. Matching literals (plus the two child prefixes below) rather
#: than bare prefixes is what keeps `/v1/resources-store` a `404` from the dispatcher instead of a route
#: this module claims, refuses differently, and thereby widens the error vocabulary.
OWNED_ROUTES = (RESOURCE_ROUTE, RESOLVE_ROUTE, DECLARATION_VALIDATION_ROUTE, OBSERVED_ROUTE, DRIFT_ROUTE,
                PROPOSAL_ROUTE, SIGNAL_ROUTE, TOPOLOGY_ROUTE, CAPABILITY_ROUTE, RULE_VALIDATION_ROUTE,
                DETECTION_EVALUATION_ROUTE, SUSTAINED_EVALUATION_ROUTE, CONFIG_DRIFT_COMPARISON_ROUTE,
                PATHCHECK_EVALUATION_ROUTE, SLO_EVALUATION_ROUTE, FORECAST_EVALUATION_ROUTE, LOCK_ROUTE,
                PLAN_ROUTE, RENDER_ROUTE, DASHBOARD_EXPORT_ROUTE)
OWNED_PREFIXES = (RESOURCE_CHILD_PREFIX, PROPOSAL_CHILD_PREFIX)

#: Every `POST` this family answers. Naming a route here is what opts it into the idempotency claim and
#: `api_contract.assert_no_actor_claim`, so the dry runs are listed too even though they write nothing and
#: need no replay: the one guarantee worth having on every write-shaped request is that a body may not name
#: the actor who sent it. A client that sends no key costs nothing — the claim is opt-in.
GUARDED_POSTS = (DECLARATION_VALIDATION_ROUTE, OBSERVED_ROUTE, PROPOSAL_ROUTE, RULE_VALIDATION_ROUTE,
                 DETECTION_EVALUATION_ROUTE, SUSTAINED_EVALUATION_ROUTE, CONFIG_DRIFT_COMPARISON_ROUTE,
                 PATHCHECK_EVALUATION_ROUTE, SLO_EVALUATION_ROUTE, FORECAST_EVALUATION_ROUTE, LOCK_ROUTE,
                 PLAN_ROUTE, RENDER_ROUTE, DASHBOARD_EXPORT_ROUTE)

# --------------------------------------------------------------------------------------- roles, bounds

READ_ROLES = ('reader', 'proposer', 'human', 'executor')
#: The identity a rule's verdict is filed under. Every evaluation below stamps its previewed events with
#: the credential's own identity, because that is the identity the producer loop files them as — so the
#: role that could file such an event is the role that may preview one. A `reader` may not, and `human`
#: does not file events at all (the state layer refuses it); neither is weakened by this list.
RULE_ROLES = ('producer',)
#: Validation builds a rule without judging a series, which is the drafting step: the producer that runs
#: the rule and the proposer that files the change it belongs to are the two identities that want it.
RULE_AUTHOR_ROLES = ('producer', 'proposer')
#: A plan, lock, rendering or dashboard export is a step in a change somebody will decide on. `proposer`
#: files changes and `human` decides them; `executor` runs approved work and never authors what it runs,
#: and a `reader` reads rather than drafts.
CONFIG_ROLES = ('proposer', 'human')
#: The role that may draft a proposal: the same one `/v1/actions` files a proposal under.
PROPOSAL_ROLES = ('proposer',)

#: The alias vocabulary of `lo-inventory resolve`, spelled once in the inventory schemas. An alias type
#: outside it is refused rather than looked up, because a lookup that accepted `host_name` would answer
#: "no such resource" about a typo — and those two facts have different fixes.
ALIAS_TYPES = ('hostname', 'host.id', 'ip', 'legacy_id', 'service.name')
#: The closed filter set of `/v1/resources`. `kind` is the inventory vocabulary; `name` is an exact match,
#: because a substring filter invites a caller to read a partial answer as a population.
RESOURCE_FILTERS = ('kind', 'name')
#: Snapshots one history page may carry. `discovery.history` reads and parses every payload whole, and a
#: snapshot may hold 10 000 observations, so this bound is on *what one request may cost*, not on what the
#: store can hold (whose own ceiling is 1 000 rows).
SNAPSHOT_LIMIT_MAX = 20
SNAPSHOT_LIMIT_DEFAULT = 10
#: Sources one drift evaluation may compare at once, and the freshness bound of the observed plane.
DRIFT_SOURCES_MAX = 8
MAX_AGE_SECONDS = 604800
#: How far a topology read may reach. `topology.MAX_DEPTH`/`MAX_ROWS` are the walk's own ceilings; these
#: are the bounds this surface exposes, matching the MCP tool's declaration so the two cannot disagree
#: about what a caller may ask for.
TOPOLOGY_DIRECTIONS = ('upstream', 'impact')
TOPOLOGY_DEPTH_BOUNDS = (1, 4)
#: A window for a preview whose producer would align it to its own tick grid. 300 seconds is that grid's
#: default (`conditions.DEFAULT_TICK_SECONDS`, `configdrift.DEFAULT_TICK_SECONDS`,
#: `pathcheck.DEFAULT_TICK_SECONDS`), imported rather than repeated as a bare number.
PREVIEW_WINDOW_SECONDS = conditions.DEFAULT_TICK_SECONDS
#: Raw query bytes admitted before parsing — the bound the page helper uses, applied to every read here.
MAX_QUERY_BYTES = api_contract.MAX_QUERY_BYTES
#: The dependency a *reported* capability and never a runtime requirement of this module: the Sigma
#: compiler lives in the optional `sigma` extra, and the only honest thing to say about an absent one is
#: that it is absent. Nothing here imports it, compiles with it, or runs what it produced.
SIGMA_EXTRA = 'sigma'
#: Rule families this door can build a rule for, because each has a document-to-object builder that every
#: producer round already runs. `pathcheck`'s configuration is a file its worker reads
#: (`LO_PATHCHECK_CONFIG`) and Sigma rules are compiled by the pinned compiler tier; both are refused
#: here rather than half-parsed, which would be a second, laxer validator.
RULE_FAMILIES = ('detection', 'sustained', 'slo', 'forecast', 'config_drift')

#: Every route this family serves, as the capability read reports it. One table, so the capability list,
#: the contract and the dispatcher cannot become three answers to "what is served here".
OPERATION_ROUTES: tuple[dict[str, str], ...] = (
    {'operation_id': 'resource.inventory.read', 'method': 'GET', 'route': '/v1/inventory'},
    {'operation_id': 'resource.read', 'method': 'GET', 'route': RESOURCE_ROUTE},
    {'operation_id': 'resource.alias.resolve', 'method': 'GET', 'route': RESOLVE_ROUTE},
    {'operation_id': 'resource.dependents.read', 'method': 'GET',
     'route': '/v1/resources/{id}/dependents'},
    {'operation_id': 'resource.declaration.validate', 'method': 'POST',
     'route': DECLARATION_VALIDATION_ROUTE},
    {'operation_id': 'resource.observation.record', 'method': 'POST', 'route': OBSERVED_ROUTE},
    {'operation_id': 'resource.observation.history.read', 'method': 'GET', 'route': OBSERVED_ROUTE},
    {'operation_id': 'resource.drift.evaluate', 'method': 'GET', 'route': DRIFT_ROUTE},
    {'operation_id': 'resource.proposal.build', 'method': 'POST', 'route': PROPOSAL_ROUTE},
    {'operation_id': 'resource.proposal.read', 'method': 'GET', 'route': '/v1/resource-proposals/{id}'},
    {'operation_id': 'resource.query.series', 'method': 'GET', 'route': SIGNAL_ROUTE},
    {'operation_id': 'resource.query.topology', 'method': 'GET', 'route': TOPOLOGY_ROUTE},
    {'operation_id': 'resource.capability.read', 'method': 'GET', 'route': CAPABILITY_ROUTE},
    {'operation_id': 'rule.validate', 'method': 'POST', 'route': RULE_VALIDATION_ROUTE},
    {'operation_id': 'rule.detection.evaluate', 'method': 'POST', 'route': DETECTION_EVALUATION_ROUTE},
    {'operation_id': 'rule.sustained.evaluate', 'method': 'POST', 'route': SUSTAINED_EVALUATION_ROUTE},
    {'operation_id': 'rule.config_drift.evaluate', 'method': 'POST',
     'route': CONFIG_DRIFT_COMPARISON_ROUTE},
    {'operation_id': 'rule.pathcheck.evaluate', 'method': 'POST', 'route': PATHCHECK_EVALUATION_ROUTE},
    {'operation_id': 'rule.slo.evaluate', 'method': 'POST', 'route': SLO_EVALUATION_ROUTE},
    {'operation_id': 'rule.forecast.evaluate', 'method': 'POST', 'route': FORECAST_EVALUATION_ROUTE},
    {'operation_id': 'config.deployment.lock', 'method': 'POST', 'route': LOCK_ROUTE},
    {'operation_id': 'config.deployment.plan', 'method': 'POST', 'route': PLAN_ROUTE},
    {'operation_id': 'config.deployment.render', 'method': 'POST', 'route': RENDER_ROUTE},
    {'operation_id': 'config.dashboard.export', 'method': 'POST', 'route': DASHBOARD_EXPORT_ROUTE},
)

#: The operations this family refuses to serve over HTTP, with the reason and the command that does the
#: job. They are named in one read rather than left as absent routes: `docs/api/COVERAGE.md` records that
#: "nobody thought of it" and "we refused it" must not look the same in five years, and a caller who can
#: ask should not have to guess which of the two a missing route is.
DECLINES: dict[str, dict[str, str]] = {
    'resource.index.build': {
        'reason': 'The built index is an input to this service, not an output of it: boot resolves action '
                  'targets in that file, so it must already exist. Rebuilding it over HTTP would also make '
                  'a bearer credential the writer of the identity graph every approval binds.',
        'instead': 'lo-inventory build <declarations> --output <path> --revision <label>',
    },
    'resource.discovery.docker': {
        'reason': 'It reads a Docker daemon socket at a path the caller names. A route that proxied reads '
                  'to a socket chosen by a request is an unvalidated backend proxy, whatever it returns.',
        'instead': 'lo-inventory discover-docker --socket <path> --expected-root <root> --project <name>',
    },
    'resource.proposal.publish': {
        'reason': 'It posts a document to a repository URL with a credential read from a file path, both '
                  'supplied by the caller: that is an outbound proxy for a mounted token, and the review '
                  'it would skip is the point of the proposal.',
        'instead': 'lo-inventory publish-proposal --proposal <file> --url <api> --repository <name>',
    },
    'config.deployment.export': {
        'reason': 'Three of its four verbs read a Docker daemon through a subprocess or call a SigNoz URL '
                  'with a mounted token. Over HTTP those become a caller-chosen command line and a '
                  'caller-chosen endpoint; `config.dashboard.export` is the one verb that is a pure '
                  'function, and it is served.',
        'instead': 'lo-deployment export-storage|export-signoz|export-homepage|export-dashboard',
    },
    'rule.sigma.compile': {
        'reason': 'It turns an unreviewed rule document into SQL text. The reviewed artifact in this '
                  'product is the *committed, pinned* compilation beside the rule, and no surface here '
                  'accepts or emits a statement.',
        'instead': 'the pinned Sigma compiler tier (local_observe/platform/sigma_compile.py, components/'
                   'control/sigma), whose output is committed with the rule',
    },
}


# ------------------------------------------------------------------------------------- entry predicates


def owns(path: str) -> bool:
    """Whether this family answers ``path`` — asked before any credential is consulted.

    A literal, or a path under one of the two child prefixes: `owns` deliberately does not answer
    `/v1/inventory` (which `api.py` has always served itself) and does not claim a path that merely
    starts like one of its names.
    """
    if path in OWNED_ROUTES:
        return True
    return any(path.startswith(prefix) for prefix in OWNED_PREFIXES)


def writes(path: str) -> bool:
    """Whether one `POST` is guarded by the idempotency and actor-claim boundary."""
    return path in GUARDED_POSTS


# ----------------------------------------------------------------------------------------- the route seam


class ResourcesAPI:
    """The route groups above, over the artifacts this process was assembled with.

    Args:
        index_path: The built inventory index (``LO_INDEX_PATH``), or ``None``. The index is an *input* to
            this service, never something a request may rebuild: ``lo-inventory build`` runs before the
            platform boots, because the action policy that boot requires resolves targets in that file.
        observed_path: The observed dataset (``LO_OBSERVED_PATH``), or ``None``.
        proposals_path: A directory proposals may be written to (``LO_PROPOSALS_PATH``), or ``None``.
        reader: A ``store.client.StoreClient`` for the bounded signal reads, or ``None``. An absent reader
            is not an error: the ``docs/CONTRACTS.md`` §2 envelope carries its own reason.

    Nothing in this file is a second writer of platform state. The only durable traces any route here can
    leave are a proposal document under ``proposals_path`` and a snapshot row in ``observed_path``, both
    written by ``local_observe.inventory`` functions the CLI uses. The operational SQLite file is never
    opened from here, which is also why no migration belongs to this family.
    """

    def __init__(self, *, index_path: Path | str | None = None, observed_path: Path | str | None = None,
                 proposals_path: Path | str | None = None, reader: Any = None) -> None:
        self.index_path = index_path
        self.observed_path = observed_path
        self.proposals_path = proposals_path
        self.reader = reader

    # --------------------------------- reads. One branch per documented path; nothing else decides a route.

    def read(self, path: str, query: bytes, actor: Actor) -> tuple[int, dict[str, Any]]:
        """Answer one resource, query or capability read, or raise the refusal the transport renders."""
        _require(actor, READ_ROLES)
        if path == RESOURCE_ROUTE:
            return 200, self._resources(query)
        if path == RESOLVE_ROUTE:
            return 200, self._resolve(query)
        if path == OBSERVED_ROUTE:
            return 200, self._snapshot_history(query)
        if path == DRIFT_ROUTE:
            return 200, self._drift(query)
        if path == SIGNAL_ROUTE:
            return 200, self._signals(query, actor)
        if path == TOPOLOGY_ROUTE:
            return 200, self._topology(query, actor)
        if path == CAPABILITY_ROUTE:
            return 200, self.capabilities()
        if path.startswith(RESOURCE_CHILD_PREFIX):
            return 200, self._dependents(path, query)
        if path.startswith(PROPOSAL_CHILD_PREFIX):
            return 200, self._proposal_read(path)
        raise _not_found()

    # ------------------------------------------------------------------------------------ writes, dry runs

    def write(self, path: str, body: dict[str, Any], actor: Actor) -> tuple[int, dict[str, Any]]:
        """Apply one write or dry run and report what *this* request did — never more than it did.

        A verb this family does not carry on a path it owns is a `405`, answered in the flat
        `{"error": "method_not_allowed"}` shape every other route in the transport uses for it. That is a
        deliberate exception to "new routes speak the envelope": the verb refusal belongs to the transport's
        vocabulary, and giving one path a second body for `405` would put the same status behind two shapes.
        """
        if path in GET_ONLY_ROUTES or _read_only_shape(path):
            return _METHOD_NOT_ALLOWED
        if path == DECLARATION_VALIDATION_ROUTE:
            _require(actor, READ_ROLES)
            return 200, self._validate_declaration(body)
        if path == OBSERVED_ROUTE:
            return 200, self._ingest(body, actor)
        if path == PROPOSAL_ROUTE:
            _require(actor, PROPOSAL_ROLES)
            return 200, self._propose(body)
        if path == RULE_VALIDATION_ROUTE:
            _require(actor, RULE_AUTHOR_ROLES)
            return 200, self._validate_rule(body, actor)
        if path == DETECTION_EVALUATION_ROUTE:
            _require(actor, RULE_ROLES)
            return 200, self._evaluate_detection(body, actor)
        if path == SUSTAINED_EVALUATION_ROUTE:
            _require(actor, RULE_ROLES)
            return 200, self._evaluate_sustained(body, actor)
        if path == CONFIG_DRIFT_COMPARISON_ROUTE:
            _require(actor, RULE_ROLES)
            return 200, self._compare_config(body, actor)
        if path == PATHCHECK_EVALUATION_ROUTE:
            _require(actor, RULE_ROLES)
            return 200, self._evaluate_pathcheck(body, actor)
        if path == SLO_EVALUATION_ROUTE:
            _require(actor, RULE_ROLES)
            return 200, self._evaluate_slo(body, actor)
        if path == FORECAST_EVALUATION_ROUTE:
            _require(actor, RULE_ROLES)
            return 200, self._evaluate_forecast(body, actor)
        if path == LOCK_ROUTE:
            return 200, self._lock(body, actor)
        if path == RENDER_ROUTE:
            return 200, self._render(body, actor)
        if path == PLAN_ROUTE:
            return 200, self._plan(body, actor)
        if path == DASHBOARD_EXPORT_ROUTE:
            return 200, self._dashboard_export(body, actor)
        raise _not_found()

    # ----------------------------------------------------------------------------------- declared plane

    def observed_statement(self) -> tuple[bool, str | None]:
        """Say whether the observed dataset can be read *now*, and name the reason when it cannot.

        Two different absences arrive at the same answer, and the caller needs to tell them apart from the
        sentence alone: the mount variable was never set, and the variable was set but the file has never
        been created because no producer has filed a snapshot yet. Both refuse a read, neither is a bug,
        and neither may be answered with an empty list that reads as "nothing was observed".
        """
        if not self.observed_path:
            return False, NO_OBSERVED
        if not Path(self.observed_path).exists():
            return False, OBSERVED_NOT_YET
        return True, None

    def index_metadata(self) -> dict[str, Any]:
        """Return what the served index says about itself, or the statement that none is mounted.

        Every answer in this family carries this block, and a `None` in it is a fact about the file rather
        than a gap in the projection: an index written by this build always records its declaration
        revision, its digest and its build instant.
        """
        if not self.index_path:
            return {'plane': 'declared', 'source': 'built inventory index', 'mounted': False,
                    'declaration_revision': None, 'declaration_sha256': None, 'built_at': None,
                    'index_schema': None, 'unavailable': NO_INDEX}
        with index.readonly(self.index_path) as connection:
            rows = dict(connection.execute('SELECT key, value FROM build_metadata').fetchall())
        return {'plane': 'declared', 'source': 'built inventory index', 'mounted': True,
                'declaration_revision': rows.get('declaration_revision'),
                'declaration_sha256': rows.get('declaration_sha256'), 'built_at': rows.get('built_at'),
                'index_schema': index.SCHEMA_VERSION, 'unavailable': None}

    def _resources(self, query: bytes) -> dict[str, Any]:
        """One bounded, filtered page of declared resources.

        Paging is by offset *within one declaration digest*: the cursor carries the first twelve characters
        of the index's ``declaration_sha256`` beside its offset, and a cursor issued against an index this
        build no longer serves is refused rather than honoured. A rebuilt index is a different population,
        and continuing a walk across it would silently skip or repeat rows — which is what a truncated
        answer must never be allowed to look like.
        """
        ask = _query(query, {'limit': 'limit', 'cursor': 'cursor',
                             **{name: 'filter' for name in RESOURCE_FILTERS}})
        metadata = self.index_metadata()
        if not metadata['mounted']:
            return _unavailable_read(metadata, limit=ask['limit'])
        where, parameters = [], []
        for name in RESOURCE_FILTERS:
            if name in ask:
                where.append(f'{name}=?')
                parameters.append(ask[name])
        clause = (' WHERE ' + ' AND '.join(where)) if where else ''
        offset = _cursor_offset(ask.get('cursor'), metadata['declaration_sha256'])
        with index.readonly(self.index_path) as connection:
            total = connection.execute('SELECT count(*) FROM resources' + clause, parameters).fetchone()[0]
            rows = connection.execute(
                'SELECT id, kind, name, owner FROM resources' + clause +
                ' ORDER BY name, id LIMIT ? OFFSET ?', [*parameters, ask['limit'] + 1, offset]).fetchall()
            page = [dict(row) for row in rows[:ask['limit']]]
            for row in page:
                row['aliases'] = [dict(item) for item in connection.execute(
                    'SELECT scope, type, value FROM aliases WHERE resource_id=? ORDER BY scope, type, value',
                    (row['id'],)).fetchall()]
                row['relation_count'] = connection.execute(
                    'SELECT count(*) FROM relations WHERE source_id=?', (row['id'],)).fetchone()[0]
        more = len(rows) > ask['limit']
        payload = _read_document(rows=page, limit=ask['limit'], returned=len(page), truncated=more,
                                 provenance=metadata)
        payload['filtered'] = bool(where)
        payload['rows_total'] = total
        payload['filters'] = {name: ask[name] for name in RESOURCE_FILTERS if name in ask}
        if more:
            payload['next_cursor'] = api_contract.encode_cursor(
                f'{_digest_tag(metadata)}:{offset + len(page)}')
        return payload

    def _dependents(self, path: str, query: bytes) -> dict[str, Any]:
        """What transitively depends on one declared resource — `inventory.index.dependents`, the read
        `lo-inventory dependents` runs, with its own `truncated` flag kept.

        An identifier that is not canonical and an identifier the index does not declare answer the same
        `404`, so this route is not an oracle for which identifiers this installation has ever accepted.
        """
        segments = path.removeprefix(RESOURCE_CHILD_PREFIX).split('/')
        if len(segments) != 2 or not segments[0] or segments[1] != 'dependents':
            raise _not_found()
        ask = _query(query, {'limit': 'limit'})
        # The identifier is judged before the mount is, so `/v1/resources/nonsense/dependents` learns `404`
        # whether or not an index is mounted. Refusing differently once an operator mounts one would make the
        # route's own error vocabulary a function of the installation, which is a surprise nobody asked for.
        resource_id = _known_identifier(segments[0])
        metadata = self.index_metadata()
        if not metadata['mounted']:
            return {**_unavailable_read(metadata, limit=ask['limit']), 'resource_id': resource_id,
                    'relation_types': list(DEPENDENT_RELATIONS)}
        try:
            with index.readonly(self.index_path) as connection:
                answer = index.dependents(connection, resource_id, min(ask['limit'], 1000))
        except InvalidInventory as refusal:
            if 'Unknown resource' in str(refusal):
                raise _missing('No declared resource carries that identifier') from refusal
            raise _bad_request(str(refusal)) from refusal
        payload = _read_document(rows=answer['resources'], limit=ask['limit'],
                                 returned=len(answer['resources']), truncated=bool(answer['truncated']),
                                 provenance=metadata)
        payload['resource_id'] = resource_id
        payload['relation_types'] = list(DEPENDENT_RELATIONS)
        return payload

    def _resolve(self, query: bytes) -> dict[str, Any]:
        """Which declared resource one alias or identifier names — `inventory.index.resolve`'s four answers.

        `unknown`, `conflict`, `unknown_uuid` and `resolved` are the store's words and are shipped as it
        wrote them: an alias that matches two resources is a *collision* and is reported with both
        candidates, never resolved by a tie-break nobody agreed to (§3: alias collisions are rejected or
        surfaced as unresolved, not silently merged).
        """
        ask = _query(query, {'id': 'filter', 'alias_type': 'filter', 'alias_value': 'filter',
                             'scope': 'filter'})
        metadata = self.index_metadata()
        if not metadata['mounted']:
            return {**_unavailable_read(metadata, limit=None), 'resource_id': None, 'candidates': []}
        if 'id' in ask and ('alias_type' in ask or 'alias_value' in ask):
            raise _bad_request('Name either a resource identifier or one alias, not both')
        aliases: list[dict[str, str]] = []
        resource_id: str | None = None
        if 'alias_type' in ask or 'alias_value' in ask:
            if 'alias_type' not in ask or 'alias_value' not in ask:
                raise _bad_request('An alias read needs both its type and its value')
            if ask['alias_type'] not in ALIAS_TYPES:
                raise _bad_request('alias_type must be one of ' + ', '.join(ALIAS_TYPES))
            aliases = [{'type': ask['alias_type'], 'value': ask['alias_value'], 'scope': ask.get('scope', '')}]
        elif 'id' in ask:
            resource_id = _known_identifier(ask['id'])
        else:
            raise _bad_request('A resource read names an identifier or an alias')
        with index.readonly(self.index_path) as connection:
            answer = index.resolve(connection, resource_id=resource_id, aliases=aliases)
            record = None
            if answer['resource_id']:
                row = connection.execute('SELECT id, kind, name, owner FROM resources WHERE id=?',
                                         (answer['resource_id'],)).fetchone()
                record = dict(row) if row else None
        return {'schema_version': 1, 'plane': 'declared', 'status': answer['status'],
                'resource_id': answer['resource_id'], 'candidates': answer['candidates'],
                'resource': record, 'truncated': False, 'complete': True, 'provenance': metadata}

    # ---------------------------------------------------------------------------------- declared against
    # ------------------------------------------------------------------------------- observed

    def _validate_declaration(self, body: dict[str, Any]) -> dict[str, Any]:
        """Judge a draft declaration with the validator the builder itself runs.

        `validation.declared` is exactly what `lo-inventory build` calls before it writes an index, so
        `valid` here means the builder will accept the document — not merely that a second, possibly
        laxer, check did. An **invalid draft is a `200`**: the caller asked a question and this route
        answered it. A `400` stays reserved for a request that never asked a valid question (a body with no
        declaration, a declaration that is not an object), which is the difference between a refusal and a
        verdict.

        The `declaration_sha256` is the digest of the *normalised* document, which is the value the built
        index would record and the value a later drift report cites. Two drafts that differ only in key
        order therefore agree, and a caller can pin a draft by its digest before a human reviews it.
        """
        _reject_keys(body, ('declaration',), 'A declaration check')
        if 'declaration' not in body:
            raise _bad_request('A declaration check names the declaration to check')
        document = body['declaration']
        if not isinstance(document, dict):
            raise _bad_request('declaration must be a JSON object')
        try:
            judged = validation.declared(document)
        except InvalidInventory as refusal:
            # The validator's sentences name the field that failed *in the document the caller sent*, which
            # is the caller's own material; they are the platform's fixed wording, so they travel.
            return {'schema_version': 1, 'status': 'invalid', 'recorded': False, 'resources': 0,
                    'declaration_sha256': None, 'kinds': [], 'complete': True,
                    'reason': str(refusal)[:300]}
        except (ValueError, KeyError, TypeError) as fault:
            # An unreadable document is still the caller's problem, but the sentence would name a Python
            # type rather than a field: say which class refused and let the log hold the traceback.
            return {'schema_version': 1, 'status': 'invalid', 'recorded': False, 'resources': 0,
                    'declaration_sha256': None, 'kinds': [], 'complete': True,
                    'reason': f'document could not be read ({type(fault).__name__})'}
        return {'schema_version': 1, 'status': 'valid', 'recorded': False,
                'resources': len(judged['resources']),
                'declaration_sha256': digest(index.normalized(judged)),
                'kinds': sorted({row['kind'] for row in judged['resources']}), 'complete': True}

    def _ingest(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """Record one discovery snapshot through `discovery.ingest` — the function `lo-inventory observe` calls.

        Two gates belong here rather than in the caller's hands:

        * **The snapshot's source is the credential.** `body['source']` must equal the authenticated
          identity, exactly as `/v1/intake/<source>` requires its path to name the caller. An observed row
          is the evidence half of a later drift finding, and a token able to file another source's
          observations would make "which prober saw this?" a claim about a payload field.
        * **The document is validated before anything is written.** `discovery.ingest` calls
          `validation.observed` first and opens no file until it passes, so a rejected snapshot costs
          nothing and leaves no half-written row behind.

        A replayed snapshot id with identical contents is answered `duplicate`, not refused: the row is
        keyed on `(source, snapshot_id)` and its payload digest, which is the same promise
        `Store.intake` makes about `source_event_id`.
        """
        _require(actor, ('producer',))
        if not self.observed_path:
            raise api_contract.ContractError(503, 'operation_unavailable', NO_OBSERVED)
        source = body.get('source')
        if not isinstance(source, str) or not source:
            raise _bad_request('An observed snapshot names the source that saw it')
        if source != actor.identity:
            raise api_contract.ContractError(403, 'not_authorised',
                                             'Source identity differs from authenticated producer')
        try:
            result = discovery.ingest(self.observed_path, body, now=clock())
        except InvalidInventory as refusal:
            # Two of `discovery.ingest`'s sentences are not about a malformed document: the row this source
            # already filed contradicts this one. That is a conflict — the caller's retry lost the race with
            # its own earlier write — and a 400 would tell someone to edit a body that is fine. Matched on
            # this module's fixed wording, the way the dependents read matches 'Unknown resource'.
            if str(refusal) in ('Snapshot replay changed its contents',
                                'Conflicting snapshots at the same source timestamp'):
                raise api_contract.ContractError(
                    409, 'conflict',
                    'That snapshot identifier already holds different evidence from this source. A new '
                    'observation files a new snapshot identifier; the one already stored stays, because a '
                    'drift finding may cite it') from refusal
            raise _bad_request(str(refusal)) from refusal
        return {'schema_version': 1, 'plane': 'observed', 'status': result['status'],
                'snapshot_id': result['snapshot_id'],
                'observations': len(body.get('observations', [])),
                'complete': bool(body.get('complete', False)),
                'recorded': True, 'declarations_touched': 0,
                'provenance': {'plane': 'observed', 'source': 'observed dataset', 'mounted': True,
                               'unavailable': None}}

    def _snapshot_history(self, query: bytes) -> dict[str, Any]:
        """The newest snapshots of one source, as summaries. `discovery.history`, bounded for the wire.

        Each row is a *summary* of a stored snapshot and never the snapshot: one observation set may hold
        10 000 rows, so a read that shipped whole snapshots would make "how fresh is the observed plane?"
        an expensive question. The snapshot itself is judged by the drift read, and `snapshot_id` names it.

        Completeness is claimed only when the store answered short. A page exactly as wide as the bound
        cannot say whether an older snapshot exists — `history` has no continuation — so `truncated` is
        true there and a caller must page by *time*, by narrowing nothing and asking again after a lower
        bound, rather than pretend a cursor exists.
        """
        ask = _query(query, {'source': 'filter', 'limit': 'small_limit'})
        if 'source' not in ask:
            raise _bad_request('A snapshot history read names its source')
        source = _inventory_name(ask['source'], 'Observed source')
        present, refusal = self.observed_statement()
        provenance = {'plane': 'observed', 'source': 'observed dataset', 'mounted': present,
                      'unavailable': refusal}
        if not present:
            return {**_unavailable_read(provenance, limit=None), 'source': source}
        limit = min(ask['limit'], SNAPSHOT_LIMIT_MAX)
        try:
            snapshots = discovery.history(self.observed_path, source, limit=max(limit, 2))
        except InvalidInventory as refusal:
            raise _bad_request(str(refusal)) from refusal
        rows = [{'source': item['source'], 'snapshot_id': item['snapshot_id'],
                 'observed_at': item['observed_at'], 'status': item['status'],
                 'complete': bool(item['complete']), 'error_code': item.get('error_code'),
                 'scope': len(item.get('scope', [])), 'observations': len(item.get('observations', []))}
                for item in snapshots[:limit]]
        payload = _read_document(rows=rows, limit=limit, returned=len(rows),
                                 truncated=len(snapshots) >= limit, provenance=provenance)
        payload['source'] = source
        payload['max_rows'] = SNAPSHOT_LIMIT_MAX
        return payload

    def _drift(self, query: bytes) -> dict[str, Any]:
        """Declared against observed, through `discovery.drift` — with per-source coverage stated.

        `drift` already says when a source is missing, stale, failed or incomplete: it emits a finding for
        each. What it does not say is whether the *answer as a whole* is a population, so this route
        projects each source's verdict into `sources` and withholds `complete: true` unless every named
        source was actually judged. An empty `findings` list from a source that never reported is therefore
        never printable as "no drift".
        """
        ask = _query(query, {'source': 'multi', 'max_age_seconds': 'filter'})
        sources = list(dict.fromkeys(ask.get('sources') or []))
        if not sources:
            raise _bad_request('A drift evaluation names at least one source')
        if len(sources) > DRIFT_SOURCES_MAX:
            raise _bad_request(f'A drift evaluation names at most {DRIFT_SOURCES_MAX} sources')
        sources = [_inventory_name(item, 'Observed source') for item in sources]
        age_text = ask.get('max_age_seconds')
        if age_text is not None and (not age_text.isdecimal() or not 1 <= int(age_text) <= MAX_AGE_SECONDS):
            raise _bad_request(f'max_age_seconds must be 1..{MAX_AGE_SECONDS}')
        age = int(age_text) if age_text is not None else 3600
        metadata = self.index_metadata()
        present, refusal = self.observed_statement()
        if not metadata['mounted'] or not present:
            missing = metadata if not metadata['mounted'] else {
                'plane': 'observed', 'source': 'observed dataset', 'mounted': False,
                'unavailable': refusal}
            return {**_unavailable_read(missing, limit=None), 'findings': [], 'sources': {},
                    'evaluated_at': utc_text(clock()), 'declaration_sha256': None,
                    'max_age_seconds': age}
        try:
            report = discovery.drift(self.index_path, self.observed_path, sources,
                                     now=clock(), max_age_seconds=age)
        except InvalidInventory as refusal:
            raise _bad_request(str(refusal)) from refusal
        coverage = {source: 'whole' for source in sources}
        for finding in report['findings']:
            if finding['kind'] in UNJUDGED_KINDS:
                coverage[finding['source']] = finding['kind']
        payload = _read_document(rows=report['findings'], limit=None, returned=len(report['findings']),
                                 truncated=any(value != 'whole' for value in coverage.values()),
                                 provenance={**metadata, 'plane': 'declared+observed'})
        payload.update({'evaluated_at': report['evaluated_at'],
                        'declaration_sha256': report['declaration_sha256'], 'sources': coverage,
                        'max_age_seconds': age,
                        'complete': all(value == 'whole' for value in coverage.values())})
        return payload

    # ---------------------------------------------------------------------------------------- the queries

    def _signals(self, query: bytes, actor: Actor) -> dict[str, Any]:
        """One bounded signal window through the same reader `signal_series` uses. No query text, ever.

        `result` is the §2 envelope a producer already emits — `rows`, `row_limit`, `truncated`, `error`,
        the half-open UTC window, and the echoed parameters — shipped unchanged, because it is the shape
        every detector, RCA bundle and MCP tool already reads. A caller with no store client mounted gets
        the same envelope with `error` naming why: "the window is empty" and "nothing was asked of the
        store" are two answers, and both are legible in one field.

        No statement, table or column name is accepted on this route at any level. The signal selects one
        approved query kind from `tools.SERIES_SIGNALS`, and the store facade builds its own SQL from that
        name — the same table the MCP tool reads, so the two surfaces cannot disagree about what may be
        asked.
        """
        from . import query as platform_query  # deferred, the way `tools.series_tool` defers it
        from .tools import SERIES_SIGNALS, SERIES_WINDOW_MINUTES
        ask = _query(query, {'signal': 'filter', 'minutes': 'filter', 'from': 'filter', 'to': 'filter',
                             'resource_id': 'filter', 'rule_id': 'filter', 'metric_name': 'filter',
                             'service': 'filter', 'artifact_sha256': 'filter'})
        signal = ask.get('signal')
        if signal not in SERIES_SIGNALS:
            raise _bad_request('signal must be one of ' + ', '.join(sorted(SERIES_SIGNALS)))
        table = SERIES_SIGNALS[signal]
        if ask.get('resource_id'):
            _known_identifier(ask['resource_id'])
        for name in ('rule_id', 'metric_name', 'service', 'artifact_sha256'):
            if ask.get(name):
                _label(ask[name])
        minutes = ask.get('minutes', '60')
        if not minutes.isdecimal() or not SERIES_WINDOW_MINUTES[0] <= int(minutes) <= SERIES_WINDOW_MINUTES[1]:
            raise _bad_request(f'minutes must be {SERIES_WINDOW_MINUTES[0]}..{SERIES_WINDOW_MINUTES[1]}')
        if ask.get('from') or ask.get('to'):
            if not (ask.get('from') and ask.get('to')):
                raise _bad_request('A signal window names both its start and its end')
            window = {'start': _instant(ask['from'], 'from'), 'end': _instant(ask['to'], 'to')}
            window_source = 'request'
        else:
            end = clock()
            window = {'start': utc_text(end - dt.timedelta(minutes=int(minutes))), 'end': utc_text(end)}
            window_source = 'relative'
        parameters = {name: ask[name] for name in ('resource_id', 'rule_id', 'artifact_sha256')
                      if ask.get(name)}
        selectors = {name: ask[name] for name in table['selectors'] if ask.get(name)}
        envelope = getattr(platform_query, table['reader'])(
            self.reader, actor.identity, table['query_type'], window=window, parameters=parameters,
            selectors=selectors)
        return {'schema_version': 1, 'signal': signal,
                'complete': envelope['error'] is None and not envelope['truncated'],
                'window_source': window_source,
                'provenance': {'query_type': table['query_type'], 'parameters': dict(parameters),
                               'window': envelope.get('window') or window, 'source': actor.identity,
                               'read_at': utc_text(clock())},
                'result': envelope}

    def _topology(self, query: bytes, actor: Actor) -> dict[str, Any]:
        """A declared neighbourhood through `topology.Topology` — the walk's own document, bounds kept.

        `truncated_by` names which bound cut the walk off (depth, rows, edges, search nodes), and is the
        only thing separating "nothing depends on this" from "the walk did not look that far". An
        undeclared identifier is refused rather than answered as an empty neighbourhood, which is the one
        difference between "no dependents" and "not a resource".

        `plane: declared` is not decoration: inferred relations live in the observed dataset and are read
        by `topology.observed_edges`, which this route deliberately does not merge into the answer.
        """
        ask = _query(query, {'resource_id': 'filter', 'direction': 'filter', 'depth': 'filter',
                             'max_rows': 'filter'})
        metadata = self.index_metadata()
        if not metadata['mounted']:
            return {**_unavailable_read(metadata, limit=None), 'plane': 'declared',
                    'direction': ask.get('direction', 'upstream'), 'result': None}
        if not ask.get('resource_id'):
            raise _bad_request('A topology read names its resource identifier')
        resource_id = _known_identifier(ask['resource_id'])
        direction = ask.get('direction', 'upstream')
        if direction not in TOPOLOGY_DIRECTIONS:
            raise _bad_request('direction must be one of ' + ', '.join(TOPOLOGY_DIRECTIONS))
        depth_text, rows_text = ask.get('depth', '2'), ask.get('max_rows', str(topology.MAX_ROWS))
        if not depth_text.isdecimal() or not TOPOLOGY_DEPTH_BOUNDS[0] <= int(depth_text) <= TOPOLOGY_DEPTH_BOUNDS[1]:
            raise _bad_request(f'depth must be {TOPOLOGY_DEPTH_BOUNDS[0]}..{TOPOLOGY_DEPTH_BOUNDS[1]}')
        if not rows_text.isdecimal() or not 1 <= int(rows_text) <= topology.MAX_ROWS:
            raise _bad_request(f'max_rows must be 1..{topology.MAX_ROWS}')
        graph = topology.Topology(self.index_path, depth=int(depth_text))
        walk = graph.upstream if direction == 'upstream' else graph.impact
        try:
            answer = walk(resource_id, depth=int(depth_text), max_rows=int(rows_text))
        except topology.UndeclaredResource as refusal:
            raise _missing(str(refusal)) from refusal
        except topology.TopologyRefusal as refusal:
            raise _bad_request(str(refusal)) from refusal
        return {'schema_version': 1, 'plane': 'declared', 'direction': direction,
                'observed_plane': 'inferred relations are read from the observed dataset, not merged here',
                'complete': not answer.get('truncated_by'), 'result': answer, 'provenance': metadata,
                'requested_by': {'identity': actor.identity, 'role': actor.role}}

    # --------------------------------------------------------------------------------------- proposals

    def _propose(self, body: dict[str, Any]) -> dict[str, Any]:
        """Draft one declaration proposal from one undeclared observation.

        `discovery.propose` is the function `lo-inventory propose` runs and it keeps all three of its
        refusals: the source's newest snapshot must be fresh and successful, the observation must be named,
        typed and free of credential material, and its aliases must resolve to *nothing* — a proposal exists
        only for an identity the declarations do not claim. What the HTTP door adds is that **the caller
        does not choose the path**: the document lands under ``LO_PROPOSALS_PATH`` named by its own proposal
        id, which is the digest of `(source, observation_id)`. A retry of the same body therefore re-reads
        the same file instead of writing a second one, and a body cannot steer a proposal somewhere this
        process was not given.

        Nothing is published, merged or declared here. The document carries `status: needs_review` because
        a proposal is an offer to a human, and the outbound half stays on the CLI.
        """
        _reject_keys(body, ('source', 'observation_id', 'max_age_seconds'), 'A proposal draft')
        if not self.proposals_path:
            raise api_contract.ContractError(503, 'operation_unavailable', NO_PROPOSALS)
        metadata = self.index_metadata()
        if not metadata['mounted']:
            raise api_contract.ContractError(503, 'operation_unavailable', NO_INDEX)
        present, refusal = self.observed_statement()
        if not present:
            raise api_contract.ContractError(503, 'operation_unavailable', refusal)
        source = _inventory_name(str(body.get('source') or ''), 'Observed source')
        observation_id = _inventory_name(str(body.get('observation_id') or ''), 'Observation id')
        age_text = body.get('max_age_seconds', 3600)
        if not isinstance(age_text, int) or isinstance(age_text, bool) or not 1 <= age_text <= MAX_AGE_SECONDS:
            raise _bad_request(f'max_age_seconds must be 1..{MAX_AGE_SECONDS}')
        key = digest({'source': source, 'observation_id': observation_id})
        output = Path(self.proposals_path) / f'{key}.json'
        try:
            proposal = discovery.propose(self.index_path, self.observed_path, source, observation_id,
                                         output, now=clock(), max_age_seconds=age_text)
        except InvalidInventory as refusal:
            # 'Proposal requires a fresh successful source snapshot', 'Only unambiguously undeclared
            # aliases can propose a new UUID' and 'Existing proposal differs; review instead of
            # overwriting' are facts about the request that the caller can act on, so they travel as a 400
            # in their own wording.
            raise _bad_request(str(refusal)) from refusal
        return {'schema_version': 1, 'status': proposal['status'], 'proposal': proposal,
                'proposal_id': key, 'written_to': output.name, 'published': False, 'declared': False,
                'complete': True, 'provenance': {**metadata, 'plane': 'declared+observed'}}

    def _proposal_read(self, path: str) -> dict[str, Any]:
        """Read one drafted proposal back, by the identifier its own content produced.

        The identifier is validated as a SHA-256 digest *before* any path is built, and the file is opened
        only inside the mounted directory: a caller may name a digest here, never a path.
        """
        key = path.removeprefix(PROPOSAL_CHILD_PREFIX).strip('/')
        if not _PROPOSAL_ID.fullmatch(key):
            raise _missing('No proposal carries that identifier')
        if not self.proposals_path:
            return {'schema_version': 1, 'status': 'unavailable', 'reason': NO_PROPOSALS,
                    'proposal_id': key, 'proposal': None, 'complete': False}
        root = Path(self.proposals_path).resolve()
        target = (root / f'{key}.json').resolve()
        if target.parent != root or not target.is_file():
            raise _missing('No proposal carries that identifier')
        try:
            proposal = json.loads(target.read_text())
        except (OSError, ValueError) as fault:
            raise api_contract.ContractError(503, 'operation_unavailable',
                                             f'The proposal could not be read ({type(fault).__name__})') from fault
        return {'schema_version': 1, 'status': str(proposal.get('status', 'unknown')),
                'proposal_id': key, 'proposal': proposal, 'published': False, 'complete': True}

    # ------------------------------------------------------------------------------------ rule lifecycle

    def _validate_rule(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """Build one rule with its own family's builder and report what it is.

        There is deliberately no second rule schema in this file. `conditions.rule`, `alerts.rule`,
        `timetothreshold.rule` and `configdrift.entry_key` are what refuse a bad rule today — every producer
        round runs them before it judges anything — so a separate validator would be a second opinion about
        the same document, free to disagree. The families below are the ones whose builder is a function of
        the document alone; `pathcheck`'s configuration is a file its own worker reads (`LO_PATHCHECK_CONFIG`)
        and Sigma rules belong to the pinned compiler tier, and both are refused rather than half-parsed.

        An invalid draft is a `400` and not a `200` verdict, which is the opposite of a declaration check —
        and that asymmetry is the point: a declaration validator *returns* a report, a rule builder only
        *raises*. When there is nothing to return but a refusal, the refusal is the answer.
        """
        _reject_keys(body, ('family', 'document'), 'A rule validation')
        family = body.get('family')
        if family not in RULE_FAMILIES:
            raise _bad_request('family must be one of ' + ', '.join(RULE_FAMILIES))
        document = _body_object(body, 'document')
        if family == 'detection':
            return self._validate_detection(document, actor)
        subject = _build_rule(family, document, actor.identity)
        return _dry_run(family=family, rule=_rule_identity(family, subject), events=[], actor=actor,
                        extra={'judged': False, 'note': 'validated; no fixture was judged'})

    def _validate_detection(self, document: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """Validate a baseline rule by running it with no sample, which is what its coverage verdict is.

        `detections.evaluate` has no separate validator — its key-set, freshness and declared-resource
        checks run at the top of the call — so the only honest answer to "is this rule well built?" is to
        run it with nothing to judge. That yields exactly one `coverage` event: a rule with no input is not
        silent, it reports that its input is absent.
        """
        metadata = self.index_metadata()
        if not metadata['mounted']:
            return _unavailable_dry_run('detection', NO_INDEX)
        try:
            events = detections.evaluate(self.index_path, document, None, now=clock())
        except (StateError, InvalidInventory, KeyError) as refusal:
            # A missing `resource_id`/`id`/`kind` reaches `detections.evaluate` as a KeyError before its
            # own sentence can be raised; the caller's omission is still their error, so it is named here
            # as a 400 rather than allowed to become a 500 wearing an exception class.
            raise _bad_request(str(refusal) if isinstance(refusal, (StateError, InvalidInventory))
                               else 'The rule document is missing a required field') from refusal
        return _dry_run(family='detection', rule={'id': document.get('id'),
                                                  'version': events[0].get('rule_version'),
                                                  'kind': 'coverage', 'mode': document.get('kind'),
                                                  'resource_id': document.get('resource_id'),
                                                  'source': document.get('source')},
                        events=events, actor=actor, extra={'judged': False})

    def _evaluate_detection(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """What one baseline rule says about one sample, with nothing filed.

        `detections.evaluate` needs the built index — a detection whose resource is not declared is a
        configuration error and refuses its round rather than filing a verdict about nothing — so with no
        index mounted this route answers `unavailable` rather than guessing at the declaration.
        """
        _reject_keys(body, ('rule', 'sample', 'window_seconds'), 'A detection evaluation')
        metadata = self.index_metadata()
        if not metadata['mounted']:
            return _unavailable_dry_run('detection', NO_INDEX)
        rule = _body_object(body, 'rule')
        sample = body.get('sample')
        if sample is not None and not isinstance(sample, dict):
            raise _bad_request('sample must be an object or absent')
        window = body.get('window_seconds', 60)
        if not isinstance(window, int) or isinstance(window, bool) or not 1 <= window <= 3600:
            raise _bad_request('window_seconds must be 1..3600')
        try:
            events = detections.evaluate(self.index_path, rule, sample, now=clock(), window_seconds=window)
        except (StateError, InvalidInventory, KeyError) as refusal:
            raise _bad_request(str(refusal) if isinstance(refusal, (StateError, InvalidInventory))
                               else 'The rule document is missing a required field') from refusal
        return _dry_run(family='detection', rule={'id': rule.get('id'), 'version': '1',
                                                  'kind': rule.get('kind'),
                                                  'resource_id': rule.get('resource_id'),
                                                  'source': rule.get('source')},
                        events=events, actor=actor,
                        extra={'window_seconds': window,
                               'judged': _reached_verdict(events)})

    def _evaluate_sustained(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """What a sustained condition says about a caller-supplied series.

        The state machine is reconstructed from the points themselves (`conditions.verdict`'s rule), so no
        cursor is read and none is written: a preview cannot make a producer's next round agree with it,
        and it is not supposed to. `points` are `[epoch_seconds, value]` pairs, bounded and ordered by
        `conditions.ordered_points` — the same function the tick judges through, so the bound is one rule
        and not two.
        """
        _reject_keys(body, ('document', 'points'), 'A sustained evaluation')
        document = _body_object(body, 'document')
        subject = _build_rule('sustained', document, actor.identity)
        try:
            events = conditions.evaluate(subject, _points(body), now=clock())
        except (StateError, ValueError) as refusal:
            raise _bad_request(f'Evaluation refused: {refusal}') from refusal
        return _dry_run(family='sustained', rule=_rule_identity('sustained', subject), events=events,
                        actor=actor, extra={'judged': _reached_verdict(events)})

    def _compare_config(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """The unified diff of one configuration artifact against the text it is compared with.

        `configdrift.compare` is the producer's own comparison and `drift_finding` the event it would file;
        the caller supplies both texts, so no snapshot tree is opened and no cursor moves. Three facts a
        reviewer needs are stated rather than assumed:

        * the digest is taken over **the UTF-8 bytes of the text in this request**, so a file whose
          newlines were translated in transit digests differently from the one on disk and reads as
          changed. That is the honest answer to "what did I send you?", not a bug to be surprised by;
        * a first sighting is not a change: `changed` is false with no `previous`, because "never seen" and
          "unchanged" are different claims;
        * the diff text is returned to *this* caller and never logged — a configuration snapshot is exactly
          the kind of file that holds a credential, which is why the producer keeps the same rule.
        """
        _reject_keys(body, ('entry', 'previous', 'current', 'window_seconds'), 'A configuration comparison')
        entry = _body_object(body, 'entry')
        current = _body_object(body, 'current')
        # The three fields this comparison and its event builder read by name. `entry_key` needs two and
        # `drift_finding` needs a third, and a `KeyError` from either would reach the transport as a 500 —
        # which is the transport's own word for "a bug happened here", not the word for "your body was
        # missing a field". Named up front, because the caller can only act on a refusal that names what it
        # left out.
        missing = sorted(name for name in ('resource_id', 'name', 'rule_id')
                         if not isinstance(entry.get(name), str) or not entry[name])
        if missing:
            raise _bad_request('The artifact entry names resource_id, name and rule_id (missing: '
                               + ', '.join(missing) + ')')
        try:
            key = configdrift.entry_key(entry)
        except (ValueError, TypeError, KeyError) as refusal:
            raise _bad_request(f'The artifact was refused: {refusal}') from refusal
        current_text = _artifact_text(current, 'current')
        snapshot = configdrift.Snapshot(resource_id=entry['resource_id'], name=entry['name'],
                                        sha256=hashlib.sha256(current_text.encode()).hexdigest(),
                                        text=current_text)
        previous = None
        if 'previous' in body:
            previous_text = _artifact_text(body['previous'], 'previous')
            previous = configdrift.LastSeen(sha256=hashlib.sha256(previous_text.encode()).hexdigest(),
                                            text=previous_text)
        window = _window(body.get('window_seconds'))
        comparison = configdrift.compare(previous, snapshot)
        finding = configdrift.drift_finding(actor.identity, entry, window, comparison) if comparison.changed \
            else None
        return {'schema_version': 1, 'family': 'config_drift', 'artifact': key,
                'changed': comparison.changed, 'previous_sha256': comparison.previous_sha256,
                'current_sha256': comparison.current_sha256, 'diff': comparison.diff,
                'digest_source': 'the UTF-8 bytes of the text carried in this request',
                'window': window, 'event_would_be': finding, 'durable': False, 'complete': True,
                'actor': {'identity': actor.identity, 'role': actor.role},
                'not_performed': ['read a snapshot tree', 'advanced a cursor', 'filed an event']}

    def _evaluate_pathcheck(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """Blast radius from a set of probe observations, classified by the producer's own classifier.

        The caller supplies the observations, so this answers "is it me or them, *given these probes*" and
        never implies the probes were taken. `pathcheck.classify` refuses an empty set — a verdict is not
        fabricated from no data — and degrades to `indeterminate` when an expected (target, vantage) pair
        said nothing, which is the answer's most important shape and is reported in `coverage_gaps` as
        well as in `notes`.
        """
        _reject_keys(body, ('observations', 'vantage_resource_id', 'expected_vantage_points',
                            'expected_targets', 'open_finding', 'window_seconds'),
                     'A pathcheck evaluation')
        rows = _body_list(body, 'observations')
        if not 1 <= len(rows) <= pathcheck.MAX_PROBES:
            raise _bad_request(f'observations must be 1..{pathcheck.MAX_PROBES}')
        vantage = _known_identifier(str(body.get('vantage_resource_id') or ''))
        observations = []
        for row in rows:
            if not isinstance(row, dict) or not {'target', 'ok'} <= set(row):
                raise _bad_request('Every observation names a target and a boolean ok')
            if 'vantage_resource_id' in row:
                _known_identifier(row['vantage_resource_id'])
            if not isinstance(row['ok'], bool):
                raise _bad_request('Every observation ok must be a boolean')
            observations.append(pathcheck.ProbeObservation(
                target=row['target'], vantage_resource_id=row.get('vantage_resource_id', vantage),
                ok=row['ok'], asn=row.get('asn'), protocol=row.get('protocol', 'icmp')))
        for item in body.get('expected_vantage_points', []):
            _known_identifier(str(item))
        for item in body.get('expected_targets', []):
            _label(str(item))
        open_finding = body.get('open_finding')
        if open_finding is not None and not isinstance(open_finding, dict):
            raise _bad_request('open_finding must be an object or absent')
        window = _window(body.get('window_seconds'))
        try:
            verdict = pathcheck.classify(observations,
                                         expected_vantage_points=tuple(body.get('expected_vantage_points', ())),
                                         expected_targets=tuple(body.get('expected_targets', ())))
            events, opening = pathcheck.verdict_findings(
                verdict, source=actor.identity, vantage_resource_id=vantage, window=window,
                observations=observations, open_finding=open_finding)
        except (pathcheck.PathCheckError, ValueError, TypeError) as refusal:
            raise _bad_request(f'Pathcheck refused: {refusal}') from refusal
        return _dry_run(
            family='pathcheck',
            rule={'id': f'{pathcheck.RULE_PREFIX}.{verdict.verdict}', 'version': None,
                  'kind': 'availability', 'mode': 'reachability', 'source': actor.identity},
            events=events, actor=actor,
            extra={'judged': True, 'verdict': verdict.verdict, 'affected': list(verdict.affected),
                   'failing': [list(pair) for pair in verdict.failing], 'notes': list(verdict.notes),
                   'coverage_gaps': [list(pair) for pair in verdict.coverage_gaps],
                   'open_after': opening, 'window': window,
                   'complete': not verdict.coverage_gaps})

    def _evaluate_slo(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """What one error-budget objective says about a caller-supplied series.

        The producer identity in the previewed events is **the credential's own**, which is why this route
        answers a `producer` and nobody else: `alerts.rule` takes the source that will file the events, so a
        preview stamped with an identity that could never file them would be a forecast about a stranger.
        """
        _reject_keys(body, ('objective', 'points'), 'An SLO evaluation')
        objective = _body_object(body, 'objective')
        subject = _build_rule('slo', objective, actor.identity)
        try:
            events = alerts.evaluate(subject, _points(body), now=clock())
        except (StateError, ValueError) as refusal:
            raise _bad_request(f'Evaluation refused: {refusal}') from refusal
        return _dry_run(family='slo', rule=_rule_identity('slo', subject), events=events, actor=actor,
                        extra={'judged': _reached_verdict(events)})

    def _evaluate_forecast(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """What one predictive rule forecasts from a caller-supplied series (its `.predicted` conditions).

        Nothing here predicts a *paging* decision. The forecast producer keeps its own cursor and its own
        sustain steps, and a preview that could advance either would be a second opinion about a window
        that has not happened; the inner threshold rule is `conditions.rule`'s, so the identity, the bounds
        and the loudness all come from the same checks.
        """
        _reject_keys(body, ('document', 'points'), 'A forecast evaluation')
        document = _body_object(body, 'document')
        subject = _build_rule('forecast', document, actor.identity)
        try:
            events = timetothreshold.evaluate(subject, _points(body), now=clock())
        except (StateError, ValueError) as refusal:
            raise _bad_request(f'Evaluation refused: {refusal}') from refusal
        return _dry_run(family='forecast', rule=_rule_identity('forecast', subject), events=events,
                        actor=actor, extra={'judged': _reached_verdict(events)})

    # ------------------------------------------------------------------------------------ configuration

    def _lock(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """Draft a content lock from the packages the caller sent, through `content.make_lock`.

        The lock is a review artifact: pins, versions and digests, with no fetch and no trust verification —
        which is what the CLI verb says on its own help line and what stays true here. Because nothing is
        fetched, the packages have to arrive in the request, and the transport caps a body at 64 KiB: a
        package set wider than that is locked by the CLI, and the `413` that results names itself.
        """
        _require(actor, CONFIG_ROLES)
        _reject_keys(body, ('packages',), 'A lock')
        packages = _body_list(body, 'packages')
        try:
            document = deployment_content.make_lock(packages)
        except deployment_content.Conflict as refusal:
            raise _bad_request(str(refusal)[:300]) from refusal
        except (KeyError, TypeError) as fault:
            raise _bad_request(f'A package was unreadable ({type(fault).__name__})') from fault
        return {**document, 'written': False, 'deploy_authorized': False,
                'requested_by': {'identity': actor.identity, 'role': actor.role}}

    def _plan(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """Compare three resolved states, through `deployment.content.plan` — the CLI's own function.

        The three documents are the caller's: what was deployed before, what is there now, and what is
        proposed. The plan's own `status` is `blocked` or `review-required` and its `deploy_authorized` is
        `false` in both cases, which is the reason the route is safe to offer: runtime drift, unmanaged
        collisions and a homepage-settings change all have to be reviewed by a human, and nothing here
        moves a state.
        """
        _require(actor, CONFIG_ROLES)
        _reject_keys(body, ('previous', 'observed', 'candidate'), 'A deployment plan')
        for name in ('previous', 'observed', 'candidate'):
            _body_object(body, name)
        try:
            result = deployment_content.plan(body['previous'], body['observed'], body['candidate'])
        except deployment_content.Conflict as refusal:
            raise _bad_request(str(refusal)[:300]) from refusal
        except (KeyError, TypeError) as fault:
            raise _bad_request(f'A state document was unreadable ({type(fault).__name__})') from fault
        return {**result, 'written': False,
                'requested_by': {'identity': actor.identity, 'role': actor.role}}

    def _render(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """Resolve a package set against its reviewed lock and return the rendered files, unwritten.

        `content.resolve` then `content.render` are the two functions `lo-deployment render` calls, in that
        order, and every one of their refusals survives here: a package set that does not match the lock
        pin for pin, an override whose `expect_sha256` no longer matches the upstream record, a tile
        pointing at a group that is not declared. What the route does **not** call is `write_bundle` — the
        answer is the file map and `written: false` says so, because the directory a deployment lands in
        stays the operator's decision, as does the size of a package set (see `413` under `_lock`).

        A `Conflict` from the resolver is a `409`: it means the caller's own three documents disagree with
        each other — usually that upstream content changed beneath an override — which is a collision with
        state the caller could not see, not a malformed request.
        """
        _require(actor, CONFIG_ROLES)
        _reject_keys(body, ('packages', 'lock', 'deployment'), 'A rendering')
        packages = _body_list(body, 'packages')
        lock = _body_object(body, 'lock')
        deployment = _body_object(body, 'deployment')
        try:
            state = deployment_content.resolve(packages, lock, deployment)
            files = deployment_content.render(state, deployment)
        except deployment_content.Conflict as refusal:
            raise api_contract.ContractError(409, 'conflict', str(refusal)[:300]) from refusal
        except (KeyError, TypeError) as fault:
            raise _bad_request(f'The content documents were unreadable ({type(fault).__name__})') from fault
        return {'schema_version': 1, 'status': 'rendered', 'lock': state['lock'],
                'deployment_sha256': state['deployment_sha256'], 'files': files,
                'file_count': len(files), 'written': False, 'deploy_authorized': False,
                'scope': 'Rendered content only; no bundle written, no state moved, no deployment',
                'requested_by': {'identity': actor.identity, 'role': actor.role}}

    def _dashboard_export(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """Project one dashboard out of a resolved state for review — `export-dashboard`'s own function.

        The answer is a *review document*: the observed digest of the pinned record, the caller's
        normalised definition, and which next step that record's ownership implies (edit a user-owned copy,
        or file a pinned-replacement override). It writes nothing and authorises nothing, exactly as the CLI
        verb does when it prints to stdout — and it is the only verb under `lo-deployment export-*` that is
        a pure function, which is why the other three are declined in `DECLINES`.
        """
        _require(actor, CONFIG_ROLES)
        _reject_keys(body, ('state', 'id', 'document'), 'A dashboard export')
        if not isinstance(body.get('id'), str):
            raise _bad_request('A dashboard export names the content identifier')
        state = _body_object(body, 'state')
        document = _body_object(body, 'document')
        try:
            result = deployment_content.export_dashboard(state, body['id'], document)
        except deployment_content.Conflict as refusal:
            raise _bad_request(str(refusal)[:300]) from refusal
        except (KeyError, TypeError) as fault:
            raise _bad_request(f'A dashboard export needs a resolved state ({type(fault).__name__})') from fault
        return {**result, 'written': False, 'deploy_authorized': False,
                'requested_by': {'identity': actor.identity, 'role': actor.role}}

    # ------------------------------------------------------------------------------------- capabilities

    def capabilities(self) -> dict[str, Any]:
        """Say, operation by operation, what this installation can do and what it will not.

        Three answers are kept apart here, because collapsing them is how a reader infers a missing feature
        from a missing mount:

        * **supported** — the route answers, and the artifact it reads is mounted.
        * **unavailable** — the route exists and answers `status: unavailable` (or `503`, for the one
          write) until an operator mounts what the entry's sentence names.
        * **excluded** — there is no route, by decision, with the reason and the command that does the job.

        The scope is *this process*. A producer that runs in its own container with its own rule document
        and cursor is invisible from here, so nothing below claims to enumerate the estate: this is the
        answer to "can I ask this service for that?", not to "does anything run anywhere?". The process's
        own counters and delivery mode stay on `GET /v1/runtime`.
        """
        metadata = self.index_metadata()
        observed_present, observed_refusal = self.observed_statement()
        readiness = {
            'resource.inventory.read': bool(self.index_path),
            'resource.read': bool(self.index_path),
            'resource.alias.resolve': bool(self.index_path),
            'resource.dependents.read': bool(self.index_path),
            'resource.declaration.validate': True,
            'resource.observation.record': bool(self.observed_path),
            'resource.observation.history.read': observed_present,
            'resource.drift.evaluate': bool(self.index_path) and observed_present,
            'resource.proposal.build': bool(self.index_path) and observed_present
            and bool(self.proposals_path),
            'resource.proposal.read': bool(self.proposals_path),
            'resource.query.series': self.reader is not None,
            'resource.query.topology': bool(self.index_path),
            'resource.capability.read': True,
            'rule.validate': True,
            'rule.detection.evaluate': bool(self.index_path),
            'rule.sustained.evaluate': True,
            'rule.config_drift.evaluate': True,
            'rule.pathcheck.evaluate': True,
            'rule.slo.evaluate': True,
            'rule.forecast.evaluate': True,
            'config.deployment.lock': True,
            'config.deployment.plan': True,
            'config.deployment.render': True,
            'config.dashboard.export': True,
        }
        operations = []
        for entry in OPERATION_ROUTES:
            name = entry['operation_id']
            item = {**entry, 'state': 'supported' if readiness.get(name) else 'unavailable'}
            if item['state'] == 'unavailable':
                item['reason'] = _mount_reason(name, metadata, observed=observed_refusal,
                                               proposals=bool(self.proposals_path),
                                               reader=self.reader is not None)
            operations.append(item)
        return {'schema_version': 1, 'reported_at': utc_text(clock()),
                'scope': 'the operations this process can answer; a producer running elsewhere with its '
                         'own rule document, cursor or mount is not enumerated here',
                'artifacts': {'inventory_index': {'mounted': bool(metadata['mounted']),
                                                  'declaration_revision': metadata['declaration_revision'],
                                                  'declaration_sha256': metadata['declaration_sha256'],
                                                  'built_at': metadata['built_at'],
                                                  'rebuilt_over_http': False},
                              'observed_dataset': {'mounted': observed_present,
                                                   'unavailable': observed_refusal},
                              'proposal_directory': {'mounted': bool(self.proposals_path)},
                              'telemetry_reader': {'mounted': self.reader is not None},
                              'sigma_compiler': {'installed': importlib.util.find_spec(SIGMA_EXTRA) is not None,
                                                 'owner': 'the pinned compiler tier; this family never '
                                                          'compiles or executes SQL'}},
                'operations': operations,
                'declines': [{'operation_id': key, **value} for key, value in DECLINES.items()],
                'complete': True, 'truncated': False}


# -------------------------------------------------------------------------------------- module helpers

#: The two relation types the transitive dependents walk follows, read out of the query it runs so the
#: answer names its own scope and a caller can tell "nothing depends on it" from "that relation is not
#: followed here".
DEPENDENT_RELATIONS = ('runs-on', 'depends-on')
#: The findings that mean a source was never judged, and so cannot support a claim of completeness.
UNJUDGED_KINDS = ('source_unavailable', 'source_stale', 'coverage_incomplete')
#: One sentence per unmounted artifact, naming the variable that mounts it. A bare "unavailable" tells an
#: operator nothing; a name they can grep in their own compose file tells them everything.
NO_INDEX = ('No built inventory index is mounted in this process (LO_INDEX_PATH); nothing here rebuilds '
            'it — lo-inventory build does')
NO_OBSERVED = 'No observed dataset is mounted in this process (LO_OBSERVED_PATH)'
#: The mount variable is set and the file it names has never been written, which is a different statement:
#: `lo-observe observed` (or `POST /v1/observed-snapshots`) creates it, and until then a read over "the
#: observed plane" has no population to describe. Answering an empty list here would say *nothing was
#: observed*, which is not what happened.
OBSERVED_NOT_YET = ('The observed dataset named by LO_OBSERVED_PATH does not exist yet: no producer has '
                    'filed a snapshot since it was mounted, so there is nothing to read')
NO_PROPOSALS = 'No proposal directory is mounted in this process (LO_PROPOSALS_PATH)'
#: The rule families whose builder needs no built index, and the ones that do.
_INDEX_BOUND_FAMILIES = ('detection',)

_METHOD_NOT_ALLOWED = (405, {'error': 'method_not_allowed'})
#: The paths on this family that only ever answer `GET`. A `POST` to one is a verb mistake, and the flat
#: `method_not_allowed` body is what every other route in the transport answers it with — a second body
#: shape for one status behind one address is the thing `api_contract.LEGACY_CODES` exists to keep honest.
GET_ONLY_ROUTES = (RESOURCE_ROUTE, RESOLVE_ROUTE, DRIFT_ROUTE, SIGNAL_ROUTE, TOPOLOGY_ROUTE,
                   CAPABILITY_ROUTE)
#: A proposal id is the digest of `(source, observation_id)` and the only way to name a proposal document
#: over HTTP, so a path can never be one.
#: The inventory's own identifier grammar, from ``local_observe/inventory/schemas``.
_INVENTORY_NAME = re.compile(r'[a-z][a-z0-9._-]{0,127}')
_PROPOSAL_ID = re.compile(r'[0-9a-f]{64}\Z')
#: The identifier shape a dependents path carries. Kept as a pattern rather than a call so a `POST` to
#: `/v1/resources/<uuid>/dependents` learns `405` (the route exists, the verb does not) while
#: `/v1/resources/<uuid>/nonsense` learns `404` (no such route) — two different facts, two answers.
_RESOURCE_ID_SHAPE = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                                r'[0-9a-fA-F]{12}\Z')


def _read_only_shape(path: str) -> bool:
    """Whether one owned path is a read that exists, and so a `POST` against it is a verb mistake."""
    if path.startswith(RESOURCE_CHILD_PREFIX):
        segments = path.removeprefix(RESOURCE_CHILD_PREFIX).split('/')
        return len(segments) == 2 and segments[1] == 'dependents' and bool(_RESOURCE_ID_SHAPE.fullmatch(
            segments[0]))
    if path.startswith(PROPOSAL_CHILD_PREFIX):
        return bool(_PROPOSAL_ID.fullmatch(path.removeprefix(PROPOSAL_CHILD_PREFIX).strip('/')))
    return False


def _require(actor: Actor, roles: tuple[str, ...]) -> None:
    """Gate a route on the credential's role, and answer 403 rather than the state layer's 400.

    `state.require` raises the platform's own sentence, which `api.py` maps to `not_authorised` at 400 — the
    answer every pre-existing route gives. A new family gets to choose, and the choice is the one a client
    can act on: 403 says "a different credential would work here", 400 says "what you sent is wrong", and
    only the second is true of a malformed body.
    """
    try:
        require(actor, *roles)
    except StateError as exc:
        raise api_contract.ContractError(403, 'not_authorised', str(exc)) from exc


def _not_found() -> api_contract.ContractError:
    """One refusal for a path this family owns but does not answer.

    It names no path: a message that echoes the request turns a routing miss into a reflection, and
    `api_contract`'s own rule is that a refusal body carries no request value.
    """
    return api_contract.ContractError(404, 'not_found', 'No such route in the resource family')


def _missing(message: str) -> api_contract.ContractError:
    return api_contract.ContractError(404, 'not_found', message)


def _bad_request(message: str) -> api_contract.ContractError:
    return api_contract.ContractError(400, 'invalid_request', str(message)[:300])


def _label(value: str) -> str:
    """Return *value* as a bounded **store** label, turning the state layer's refusal into a 400.

    The alphabet is `[a-zA-Z0-9_.:-]` and it is not this module's invention: it is the shape
    `store.client.LABEL` re-checks on every parameter and query type before a read leaves the process.
    Checking it here changes nothing about what the store will accept — it moves the refusal to the door,
    where it costs one comparison and names the field, instead of surfacing as a broken receipt deep in a
    read. It is also why a `rule_id` may not contain a hyphen here while an observed source name may: the
    first is a store parameter, the second is an inventory identifier (see :func:`_inventory_name`).
    """
    try:
        return label(value)
    except StateError as exc:
        raise _bad_request(str(exc)) from exc


def _inventory_name(value: str, what: str = 'Identifier') -> str:
    """Return *value* as an inventory identifier, the grammar the observed dataset itself enforces.

    ``^[a-z][a-z0-9._-]{0,127}$`` is copied from the inventory's own schemas, so a source named
    ``probe-source`` or an observation named ``new-service-001`` — both of which the fixture corpus
    contains and `discovery.ingest` has already accepted — can be asked about over HTTP. The store's label
    alphabet would refuse the hyphen, and refusing a name that the mounted artifact already stored would
    make this read unable to answer for its own inputs.
    """
    if not _INVENTORY_NAME.fullmatch(value or ''):
        raise _bad_request(f'{what} must match ^[a-z][a-z0-9._-]{{0,127}}$')
    return value


def _known_identifier(value: str) -> str:
    """Return *value* as a canonical UUID, refusing anything else with the 404 a lookup would give.

    `state.identifier` raises the platform's sentence, which `api.py` would classify as a 400. A path or
    query parameter that is not an identifier is answered exactly as an identifier that names nothing: the
    two are the same question to a caller, and keeping them apart would let this family report which
    identifier shapes it has ever accepted.
    """
    try:
        return identifier(value)
    except StateError as exc:
        raise _missing(str(exc)) from exc


def _instant(value: str, name: str) -> str:
    """Return *value* as the UTC text a window bound carries, refusing anything unparsable."""
    try:
        return utc_text(validation.timestamp(value))
    except (InvalidInventory, ValueError, TypeError) as exc:
        raise _bad_request(f'{name} must be a timezone-aware timestamp') from exc


def _window(seconds: Any) -> dict[str, str]:
    """Return the preview window a rule round would carry, aligned to nothing and stated as such.

    A producer aligns its window to its own tick grid; a preview has no grid, so it carries a span of the
    grid's *default* length ending now. It exists because an event's evidence reference and its expiry are
    both derived from the window: an answer with no window would be an event that could not have been
    filed, which is a worse fiction than a stated approximation.
    """
    if seconds is None:
        seconds = PREVIEW_WINDOW_SECONDS
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 1 <= seconds <= 86400:
        raise _bad_request('window_seconds must be 1..86400')
    end = clock()
    return {'start': utc_text(end - dt.timedelta(seconds=seconds)), 'end': utc_text(end)}


def _artifact_text(document: Any, name: str) -> str:
    """Return the configuration text one comparison side carries.

    An artifact is `{text}` or `{sha256, text}`: the digest is *derived here* from the bytes, never
    accepted from the caller, because a caller that could name both would be able to assert a digest that
    the text does not have — and the whole value of a drift finding is that its digest is what the bytes
    are.
    """
    if not isinstance(document, dict) or not isinstance(document.get('text'), str):
        raise _bad_request(f'{name} must carry the artifact text')
    if len(document['text'].encode()) > configdrift.MAX_SNAPSHOT_BYTES:
        raise _bad_request(f'{name} exceeds the {configdrift.MAX_SNAPSHOT_BYTES}-byte snapshot ceiling')
    return document['text']


def _build_rule(family: str, document: dict[str, Any], identity: str | None) -> Any:
    """Build one rule with its family's own builder, and turn its refusal into a 400.

    `slo` takes the producer identity because `alerts.rule` requires it; every other family takes a
    document alone. A `vocabulary.VocabularyError` from an unresolvable severity tier is a `ValueError`
    with the family's own sentence, and travels as one.
    """
    try:
        if family == 'sustained':
            return conditions.rule(document)
        if family == 'slo':
            return alerts.rule(document, source=str(identity))
        if family == 'forecast':
            return timetothreshold.rule(document)
        if family == 'config_drift':
            configdrift.entry_key(document)
            return document
    except (StateError, ValueError, TypeError, KeyError) as refusal:
        raise _bad_request(str(refusal)) from refusal
    raise _bad_request('family must be one of ' + ', '.join(RULE_FAMILIES))


def _rule_identity(family: str, subject: Any) -> dict[str, Any]:
    """Return the identity one built rule carries: the name, the version and the loudness.

    `version` is a digest of everything the judgement depends on, produced by the rule itself, so a caller
    that wants to pin "the rule I reviewed" pins this value and not the document's bytes. A forecast rule
    reports its own identity — `pool` becomes `pool.predicted` — because that is the condition its events
    carry; the inner breach rule it shares bounds with stays named in `watch_rule`.
    """
    if family == 'config_drift':
        return {'id': subject.get('rule_id'), 'version': None, 'kind': 'drift', 'mode': 'config-drift',
                'resource_id': subject.get('resource_id')}
    # `id`, `kind`, `mode` and `version` are attributes of every rule class and `severity` is the one
    # method they all share, so this reads all four families alike. A forecast rule reports its **own**
    # identity here — `pool` becomes `pool.predicted` — because that is the condition its events carry;
    # the inner threshold rule is reachable through `rule_id`, and reporting it instead would name the
    # breach a forecast is only predicting.
    identity = {'id': subject.id, 'version': subject.version, 'kind': subject.kind, 'mode': subject.mode,
                'severity': subject.severity(), 'source': subject.source,
                'resource_id': subject.resource_id}
    if family == 'forecast':
        identity.update({'model': subject.model, 'horizon_seconds': subject.horizon_seconds,
                         'watch_rule': subject.rule_id})
    return identity


def _points(body: dict[str, Any]) -> list[Any]:
    """Return the series a rule is judged over: ``[[epoch_seconds, value], ...]``, bounded and ordered.

    The points are the caller's fixture and not a store read, which is what makes a preview a preview. They
    are judged through `conditions.ordered_points`, the function every producer's tick uses, so the bound on
    how many points may be judged and the refusal of a malformed one stay one rule rather than two.
    """
    rows = _body_list(body, 'points')
    if len(rows) > conditions.MAX_POINTS:
        raise _bad_request(f'points may not exceed {conditions.MAX_POINTS}')
    pairs = []
    for row in rows:
        if not isinstance(row, list) or len(row) != 2:
            raise _bad_request('Each point is [epoch_seconds, value]')
        try:
            pairs.append((float(row[0]), row[1]))
        except (TypeError, ValueError):
            raise _bad_request('Each point starts with a numeric epoch second') from None
    try:
        return list(conditions.ordered_points(pairs))
    except (StateError, ValueError, TypeError) as refusal:
        raise _bad_request(f'The point series was refused: {refusal}') from None


def _digest_tag(metadata: dict[str, Any]) -> str:
    """Return the twelve-character index mark a page cursor carries."""
    return str(metadata.get('declaration_sha256') or '')[:12]


def _cursor_offset(cursor: str | None, sha256: str | None) -> int:
    """Return the row offset one continuation token names, refusing a token from a different index.

    Raises:
        api_contract.ContractError: 400 `invalid_pagination` when the token decodes to no offset, or to a
            mark that is not the digest of the index now being served.

    The decode itself is `api_contract.decode_cursor`'s — a token this service never issued is refused
    before a connection is opened, so a typo cannot read as "no more rows".
    """
    if cursor is None:
        return 0
    position = api_contract.decode_cursor(cursor)
    mark, separator, offset = position.partition(':')
    if not separator or not offset.isdigit() or str(int(offset)) != offset:
        raise api_contract.ContractError(400, 'invalid_pagination', api_contract.CURSOR_REJECTED)
    if mark != _digest_tag({'declaration_sha256': sha256}):
        raise api_contract.ContractError(400, 'invalid_pagination',
                                         'This page was issued against a different declaration; start again')
    return int(offset)


def _query(raw: bytes, spec: dict[str, str]) -> dict[str, Any]:
    """Return one validated query as a mapping, refusing what the table does not name.

    `api_contract.page_params` admits exactly `limit` and `cursor`, which is right for a plain page and too
    narrow for a filtered read. This helper keeps that module's rules — refuse rather than clamp, one value
    per name, ASCII percent-encoding, a byte ceiling ahead of any parsing, a cursor decoded by
    `decode_cursor` — and adds named filters from the table it is given: ``limit`` (decimal, refused above
    the page ceiling), ``small_limit`` (the same, for the reads whose bound is tighter than a page's),
    ``filter`` (exactly one value) and ``multi`` (repeatable, collected into ``sources``).

    Raises:
        api_contract.ContractError: 400 `invalid_request` or `invalid_pagination`, naming the rule and
            never the caller's bytes.
    """
    text = raw or b''
    if len(text) > MAX_QUERY_BYTES:
        raise _bad_request(f'A query may not exceed {MAX_QUERY_BYTES} bytes')
    found: dict[str, list[str]] = {}
    for item in text.split(b'&') if text else ():
        name, separator, value = item.partition(b'=')
        try:
            key = urllib.parse.unquote(name.decode('ascii'), errors='strict')
            item_value = urllib.parse.unquote(value.decode('ascii'), errors='strict')
        except (UnicodeDecodeError, UnicodeEncodeError):
            raise _bad_request('A query must be ASCII percent-encoded text') from None
        if not separator or not key or not item_value or key not in spec:
            raise _bad_request('A read query names only the parameters it names, each with a value')
        found.setdefault(key, []).append(item_value)
    ask: dict[str, Any] = {}
    for key, values in found.items():
        kind = spec[key]
        if kind == 'multi':
            ask['sources'] = [*ask.get('sources', []), *values]
            continue
        if len(values) != 1:
            raise _bad_request(f'{key} takes one value')
        ask[key] = values[0]
        if kind in ('limit', 'small_limit'):
            ceiling = api_contract.PAGE_LIMIT_MAX if kind == 'limit' else SNAPSHOT_LIMIT_MAX
            if not values[0].isdecimal() or str(int(values[0])) != values[0] or \
                    not 1 <= int(values[0]) <= ceiling:
                raise _bad_request(f'limit must be a positive integer no greater than {ceiling}')
            ask[key] = int(values[0])
        if kind == 'cursor':
            # Decoded here to *validate* the token shape, then kept raw: the route that pages needs the
            # position text `_cursor_offset` understands, and decoding twice would turn a valid cursor into
            # a refusal. A token this service never issued is still refused before a connection opens.
            api_contract.decode_cursor(values[0])
            ask[key] = values[0]
    if 'limit' in spec and 'limit' not in ask:
        ask['limit'] = api_contract.PAGE_LIMIT_DEFAULT
    if 'small_limit' in spec and 'small_limit' not in ask:
        ask['small_limit'] = SNAPSHOT_LIMIT_DEFAULT
    return ask


def _read_document(*, rows: list[Any], limit: int | None, returned: int, truncated: bool,
                   provenance: dict[str, Any]) -> dict[str, Any]:
    """One shape for every list answer here, so no route can forget that a bound is a claim.

    `complete` is the field to branch on: it is `false` whenever the answer is not the whole answer,
    whether a bound cut it off or the artifact behind it is not mounted. `truncated` says it was a bound,
    matching the vocabulary `docs/CONTRACTS.md` §2 gives a query adapter and `topology.py` gives a walk.
    `limit` is `null` where no row bound applies, which is a fact about the read and not a zero: a drift
    report is bounded by the sources named, not by a row count.
    """
    return {'schema_version': 1, 'status': 'ok', 'rows': rows, 'limit': limit, 'returned': returned,
            'truncated': truncated, 'complete': not truncated, 'provenance': provenance}


def _unavailable_read(provenance: dict[str, Any], *, limit: int | None) -> dict[str, Any]:
    """The answer of a read whose artifact is not mounted: no rows, and the reason beside them.

    A `200` with `complete: false` and `status: unavailable`, not a `404`: the route exists and answered
    honestly. A `404` would say the feature is absent from this build, which is a different fact and the
    one `GET /v1/capabilities` exists to settle.
    """
    return {'schema_version': 1, 'status': 'unavailable', 'rows': [], 'limit': limit, 'returned': 0,
            'truncated': False, 'complete': False, 'reason': provenance.get('unavailable'),
            'provenance': provenance}


def _dry_run(*, family: str, rule: dict[str, Any], events: list[dict[str, Any]], actor: Actor,
             extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """The shape every rule answer takes: what was judged, what it earned, and what did not happen.

    `events` are the canonical events the producer would hand to intake — built by the same builders, with
    the source the family uses. `durable: false` is not decoration: nothing was filed, no cursor moved, no
    page was sent, and a producer that runs this rule later files its own verdicts under its own identity.
    There is no paging here because there is no store to page over: the caller supplied the fixture, so the
    answer is whole or the read was unavailable.
    """
    return {'schema_version': 1, 'family': family, 'rule': rule, 'events': events, 'count': len(events),
            'durable': False, 'complete': True, 'truncated': False,
            'actor': {'identity': actor.identity, 'role': actor.role},
            'not_performed': ['filed an event', 'advanced a cursor', 'paged', 'delivered'],
            **(extra or {})}


def _unavailable_dry_run(family: str, reason: str) -> dict[str, Any]:
    """A rule preview that could not run, in the same shape with the same field names."""
    return {'schema_version': 1, 'family': family, 'status': 'unavailable', 'reason': reason,
            'rule': None, 'events': [], 'count': 0, 'durable': False, 'complete': False,
            'truncated': False, 'not_performed': ['filed an event', 'advanced a cursor', 'paged']}


def _body_object(body: dict[str, Any], name: str) -> dict[str, Any]:
    """Return one named body field as a mapping, refusing its absence or a non-object."""
    if name not in body:
        raise _bad_request(f'{name} is required')
    value = body[name]
    if not isinstance(value, dict):
        raise _bad_request(f'{name} must be a JSON object')
    return value


def _body_list(body: dict[str, Any], name: str) -> list[Any]:
    """Return one named body field as a list, refusing its absence or a non-list."""
    if name not in body:
        raise _bad_request(f'{name} is required')
    value = body[name]
    if not isinstance(value, list):
        raise _bad_request(f'{name} must be a JSON array')
    return value


def _reached_verdict(events: Sequence[dict[str, Any]]) -> bool:
    """Say whether a preview produced a judgement about the watched thing, or only said it could not see it.

    A `coverage`-kind event is the rule reporting on its **input** — stale, absent, refused — and it is
    deliberately the only event a rule may file when it cannot judge, so that a blind round leaves the
    stored condition exactly as it was. Reporting `judged: true` next to such an answer would be a claim
    about the resource that nothing in the answer supports, so this says true only when something else
    came with it.
    """
    return any(event['kind'] != 'coverage' for event in events)


def _reject_keys(body: dict[str, Any], allowed: tuple[str, ...], what: str) -> None:
    """Refuse a body that names a field this door does not read.

    A silently ignored field is how a contract dies quietly: the caller believes they asked for a freshness
    bound or a dry-run flag, the platform did nothing with it, and somebody discovers that later during an
    outage. The refusal names the field, because the caller owns the document and learns nothing from a
    count. (`api_contract.assert_no_actor_claim` has already refused an identity field further upstream, on
    every route this family exposes.)
    """
    extra = sorted(field for field in body if field not in allowed)
    if extra:
        raise _bad_request(f'{what} accepts only {", ".join(allowed)} (unexpected: {", ".join(extra)})')


def path_from_environment(name: str, environ: Mapping[str, str] | None = None) -> str | None:
    """Return the path one variable names, or ``None`` when it names nothing.

    Unset is the documented off switch. **Blank is a refusal**: a line reading ``LO_OBSERVED_PATH=`` in a
    generated environment file says an operator wrote it, and quietly treating that as "no observed
    plane" would let a deployment that meant to mount one answer `unavailable` forever with no clue why.
    Only the variable's name appears in the message; no value is echoed.
    """
    values = os.environ if environ is None else environ
    if name not in values:
        return None
    text = values[name].strip()
    if not text:
        raise ValueError(f'{name} is set but blank; name a path, or unset it')
    return text


def _mount_reason(operation_id: str, metadata: dict[str, Any], *, observed: str | None,
                  proposals: bool, reader: bool) -> str:
    """Name the artifact a route is waiting for, in the words the route itself would answer with.

    One function so the capability document and the route cannot describe the same missing mount in two
    different sentences — which is how a reader ends up trusting one and ignoring the other.
    """
    if not metadata['mounted']:
        return str(metadata['unavailable'])
    if operation_id == 'resource.query.series' and not reader:
        return ('No read-only store client is mounted in this process (LO_CLICKHOUSE_URL with '
                'LO_CLICKHOUSE_READ_USER/LO_CLICKHOUSE_READ_PASSWORD); the §2 envelope says so in `error`')
    if observed and operation_id in ('resource.observation.record',
                                     'resource.observation.history.read', 'resource.drift.evaluate',
                                     'resource.proposal.build'):
        return observed
    if not proposals and operation_id in ('resource.proposal.build', 'resource.proposal.read'):
        return NO_PROPOSALS
    return NO_INDEX

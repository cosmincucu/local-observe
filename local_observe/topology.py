"""Topology as a derived read model over declared relations (topology read model).

There is no graph store here and no second copy of anything: the nodes are the declared
resource UUIDs of one built inventory index (``local_observe/inventory/index.py``) and the
edges are that index's ``relations`` table, read through ``index.readonly()``. Nothing in
this module writes, caches, or persists a graph — every question is answered from the
index that was actually built, so a topology answer can never be newer or older than the
declaration revision it came from.

Direction convention (ported verbatim from v0.1's ``topology/graph.py``, because three
later consumers read this docstring and not the code):

    An edge ``src --relation--> dst`` means **src DEPENDS ON dst**.
    Example: ``container --runs-on--> host`` — the container depends on the
    host, so the host is *upstream* of the container.

    - ``upstream(id)`` follows OUTGOING depends-on edges: everything ``id``
      transitively depends on (its ancestors).
    - ``impact(id)`` follows INCOMING depends-on edges: everything that
      transitively depends on ``id`` — what breaks if ``id`` breaks.
    - ``shortest_path(a, b)`` walks the same depends-on direction (outgoing
      from ``a``), so a path exists iff ``a`` transitively depends on ``b``.

Two planes, never merged (``docs/CONTRACTS.md`` §3: alias collisions "are not silently
merged", and the observed dataset "records source, observed_at, resource aliases and
evidence"):

    * **declared** edges come from the built index and carry the *declaration revision*
      and *declaration sha256* that produced them, so a consumer can name which
      declaration an edge came from.
    * **observed** edges are *inferred* relations — span-shaped or network-shaped hints —
      and they are only ever written through the existing observed-plane path
      (``discovery.Observation`` → ``discovery.snapshot`` → ``discovery.ingest``). They
      carry ``observed_at``, the source and its evidence, and they have **no** declaration
      revision: an inference is not intent. Evidence is what makes an inference checkable,
      so it is required on both sides of the boundary: the helper refuses to build one
      without it, and ``observed_edges()`` refuses to return one it read back that way
      (``discovery.ingest`` validates against the schema, which allows an empty list).
      ``declared_edges()`` and ``observed_edges()`` are separate calls returning separate
      types, and the traversals above read the declared plane only.

Every traversal is deterministic (sorted frontier, sorted neighbours, sorted output) and
bounded in depth and rows, and a bound that cut the answer says which one: ``truncated`` is
True and ``truncated_by`` names the bound that bit (``'depth'``, ``'rows'``, ``'nodes'``). The
two kinds of stop are never conflated. A walk stopped *at* the depth limit is truncated only
when the next hop would have reached something new — a bounded existence check says so — so a
leaf sitting exactly on the boundary is still a complete answer, while ``a -> b -> c`` asked at
depth 1 is a cut answer even though ``b`` was the only node returned. ``shortest_path`` keeps a
cumulative record of the same marks across its whole search: it never calls a target absent,
and never calls a path shortest, when any earlier hop was cut.

An undeclared resource id is a refusal, never an empty neighbourhood, so an empty ``nodes``
list always means "this resource has nothing on that side" and never "the bound was reached".

A declared cycle is a finding rather than a crash: ``index.build`` validates that relation
*targets* exist (``validation.declared`` raises ``'Relation target is not declared'``) and
says nothing about cycles, so ``detect_cycles()`` is the check and ``cycle_findings()`` turns
a hit into canonical ``coverage`` events through the read-only
``platform.detections.event`` factory. What it reports are **DFS witnesses**: an empty list
from a complete scan proves the declared graph is acyclic, but a non-empty list is *not* an
enumeration of every elementary cycle in it, and the report bound makes even the witness list
partial — hence ``truncated``/``complete`` on that scan too.
"""
import datetime as dt
import hashlib
import re
import uuid as uuid_module
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from .inventory import discovery, index
from .inventory.validation import InvalidInventory, canonical, utc_text

#: The two planes, spelled once. Asking for one and receiving the other is a bug (topology read model).
DECLARED = 'declared'
OBSERVED = 'observed'

#: A caller may ask for at most this many hops; deeper is a refusal, not a silent clamp.
MAX_DEPTH = 32
#: What ``depth=None`` means on every traversal.
DEFAULT_DEPTH = 10
#: Rows (reached nodes or edges) one call returns by default.
MAX_ROWS = 200
#: The largest ``max_rows`` an argument may ask for.
ROW_CEILING = 1000
#: Edges a cycle scan will load in full; a bigger graph is refused rather than partially scanned.
MAX_EDGES = 20000
#: Cycles one call reports.
MAX_CYCLES = 100
#: Resource ids one hop query may carry (SQLite variable bound is far above this).
FRONTIER_CHUNK = 200
#: Nodes one ``shortest_path`` search may discover in total, not merely in one hop.
MAX_SEARCH_NODES = 2000
#: Rows one ``shortest_path`` search may read in total, across every hop it takes.
MAX_SEARCH_ROWS = 5000
#: Query parameters one existence check may bind. SQLite's own ceiling is far above it; reaching
#: this ceiling means the check can no longer exclude the visited set, and the answer degrades to
#: "work may remain" rather than to a false completeness claim.
SQL_PARAMETER_BOUND = 4000
#: Evidence a snapshot may carry, restated from ``inventory/schemas/observed.json``
#  (``observations.items.evidence``: ``maxItems`` 20, items ``minLength`` 1 / ``maxLength`` 1024).
#  That file is not this brief's to edit, so the bounds are pinned against it by test.
MAX_EVIDENCE_REFS = 20
MAX_EVIDENCE_CHARS = 1024

#: Same pattern as ``inventory/schemas/declared.json``'s ``relations.items.type``. That file is
#: not this brief's to edit, so the shape is restated here and pinned by a test against it.
RELATION_SHAPE = re.compile(r'^[a-z][a-z0-9-]{0,63}$')
#: Attribute names an observed-plane record uses to carry one inferred relation.
INFERRED_RELATION = 'inferred_relation'
INFERRED_TARGET = 'inferred_relation_target'
#: Rule-id prefix of the declared-cycle finding; the suffix is the cycle's own digest.
CYCLE_RULE_PREFIX = 'topology.declared-cycle'
#: Evidence reference of a cycle finding: the declaration whose build produced the graph.
CYCLE_EVIDENCE_QUERY_TYPE = 'observed-snapshot'


class TopologyRefusal(InvalidInventory):
    """A refusal this module raised on purpose. It is an ``InvalidInventory``, so an HTTP edge
    that already classifies inventory refusals as a chosen 400 classifies these the same way."""


class UndeclaredResource(TopologyRefusal):
    """A resource id that the built index does not declare. Refused, never an empty answer."""


def _node_id(value: Any, *, what: str = 'resource id') -> str:
    """Accept only a canonical lowercase UUID string; anything else is a refusal."""
    if not isinstance(value, str):
        raise TopologyRefusal(f'{what} must be a canonical UUID string')
    try:
        parsed = uuid_module.UUID(value)
    except ValueError as exc:
        raise TopologyRefusal(f'{what} is not a canonical UUID') from exc
    if str(parsed) != value:
        raise TopologyRefusal(f'{what} must be a canonical lowercase UUID')
    return value


def _bounded(name: str, value: Any, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TopologyRefusal(f'{name} must be an integer')
    if not low <= value <= high:
        raise TopologyRefusal(f'{name} must be {low}..{high}')
    return value


def _relation(value: Any) -> str:
    if not isinstance(value, str) or not RELATION_SHAPE.fullmatch(value):
        raise TopologyRefusal('Relation type must match the declared relation vocabulary')
    return value


def _evidence(value: Any) -> list[str]:
    """The evidence references of one inference, validated against the observed plane's own bounds.

    A bare ``str`` is refused rather than iterated: ``"span:abc"`` is one reference, and silently
    accepting it would have stored ``['s', 'p', 'a', ...]`` as its evidence.
    """
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Iterable):
        raise TopologyRefusal('Evidence must be a sequence of evidence references, not a single value')
    items = list(value)
    if not items:
        raise TopologyRefusal('An inferred relation needs at least one evidence reference')
    if len(items) > MAX_EVIDENCE_REFS:
        raise TopologyRefusal(f'Evidence must be at most {MAX_EVIDENCE_REFS} references')
    for item in items:
        if not isinstance(item, str) or not item.strip() or len(item) > MAX_EVIDENCE_CHARS:
            raise TopologyRefusal(f'Each evidence reference must be 1..{MAX_EVIDENCE_CHARS} characters')
    return items


def _mark(reasons: list[str], reason: str) -> None:
    """Record which bound cut a search, once, in a stable order."""
    if reason not in reasons:
        reasons.append(reason)
    reasons.sort()


def _has_unexplored(connection, frontier: Sequence[str], *, outgoing: bool, exclude: Iterable[str]) -> bool:
    """Does some edge leave ``frontier`` for a node outside ``exclude``? One bounded existence check.

    ``SELECT 1 ... LIMIT 1`` per frontier chunk — it does not walk anything, it answers "would the
    next hop have found something new?", which is the only way a walk cut by its *depth* bound can
    tell a real boundary from a natural leaf. Unknown is never reported as absent: if the exclusion
    set is too wide to bind as parameters, the answer is True and the caller says it was truncated.
    """
    parent_column, node_column = ('source_id', 'target_id') if outgoing else ('target_id', 'source_id')
    ordered, omitted = sorted(set(frontier)), sorted(set(exclude))
    room = SQL_PARAMETER_BOUND - len(omitted) - 1
    if room < 1:
        return True
    step = min(FRONTIER_CHUNK, room)
    for start in range(0, len(ordered), step):
        chunk = ordered[start:start + step]
        omitted_sql = f' AND r.{node_column} NOT IN ({", ".join("?" * len(omitted))})' if omitted else ''
        row = connection.execute(
            f'SELECT 1 FROM relations r JOIN resources s ON s.id = r.{node_column}'
            f' WHERE r.{parent_column} IN ({", ".join("?" * len(chunk))}){omitted_sql} LIMIT 1',
            (*chunk, *omitted)).fetchone()
        if row is not None:
            return True
    return False


@dataclass(frozen=True)
class DeclaredEdge:
    """One declared relation, with the declaration revision that produced it.

    ``source_id`` depends on ``target_id`` (module docstring). ``plane`` is a class
    constant, never a field: an observed edge cannot acquire it, and an inferred one
    cannot be mistaken for this.
    """

    source_id: str
    target_id: str
    relation: str
    declaration_revision: str
    declaration_sha256: str

    plane: ClassVar[str] = DECLARED

    def as_dict(self) -> dict[str, Any]:
        return {'plane': self.plane, 'source_id': self.source_id, 'target_id': self.target_id,
                'relation': self.relation, 'declaration_revision': self.declaration_revision,
                'declaration_sha256': self.declaration_sha256}


@dataclass(frozen=True)
class ObservedEdge:
    """One inferred relation as an observation: ``observed_at`` and evidence, no revision.

    It has no ``declaration_revision`` attribute at all — code that expects one on an
    observed edge fails loudly rather than reading ``None`` as "newer than declared".
    """

    source_id: str
    target_id: str
    relation: str
    observation_source: str
    observed_at: str
    snapshot_id: str
    evidence: tuple[str, ...]

    plane: ClassVar[str] = OBSERVED

    def as_dict(self) -> dict[str, Any]:
        return {'plane': self.plane, 'source_id': self.source_id, 'target_id': self.target_id,
                'relation': self.relation, 'observation_source': self.observation_source,
                'observed_at': self.observed_at, 'snapshot_id': self.snapshot_id,
                'evidence': list(self.evidence)}


class Topology:
    """Read-only questions asked of one built inventory index.

    Args:
        index_path: Path to the SQLite index ``inventory.index.build`` wrote. It is opened
            read-only per call (``index.readonly`` re-validates the application id and
            schema version every time), so a rotated index is never half-read and this
            object holds no live handle.
        depth: Default hop bound for the traversals.
        max_rows: Default row bound for one call.

    Raises:
        TopologyRefusal: An argument outside its bound. ``index.readonly`` raises
            ``InvalidInventory`` (this class's base) when the file is not an inventory index.
    """

    def __init__(self, index_path: Path | str, *, depth: int = DEFAULT_DEPTH, max_rows: int = MAX_ROWS) -> None:
        self.index_path = Path(index_path)
        self.depth = _bounded('depth', depth, 1, MAX_DEPTH)
        self.max_rows = _bounded('max_rows', max_rows, 1, ROW_CEILING)

    # -- declaration provenance -------------------------------------------

    def revision(self) -> dict[str, str]:
        """The declaration identity this index was built from; every edge result carries it."""
        with index.readonly(self.index_path) as connection:
            return self._revision(connection)

    @staticmethod
    def _revision(connection) -> dict[str, str]:
        rows = {row['key']: row['value'] for row in connection.execute('SELECT key, value FROM build_metadata')}
        missing = [name for name in ('declaration_revision', 'declaration_sha256', 'built_at') if not rows.get(name)]
        if missing:
            raise TopologyRefusal('Built index carries no ' + ', '.join(missing))
        return {'declaration_revision': rows['declaration_revision'],
                'declaration_sha256': rows['declaration_sha256'], 'built_at': rows['built_at'],
                'schema_version': rows.get('schema_version', '')}

    def _known(self, connection, resource_id: str) -> dict[str, str]:
        row = connection.execute('SELECT id, kind, name FROM resources WHERE id=?', (resource_id,)).fetchone()
        if row is None:
            raise UndeclaredResource(f'Resource {resource_id} is not declared in this index')
        return {'resource_id': row['id'], 'kind': row['kind'], 'name': row['name']}

    # -- the declared plane ------------------------------------------------

    def declared_edges(self, *, resource_id: str | None = None, relation: str | None = None,
                       max_rows: int | None = None) -> dict[str, Any]:
        """Every declared edge, or the ones touching one resource; ordered and bounded.

        Args:
            resource_id: Restrict to edges where this id is either endpoint. An undeclared
                id is refused.
            relation: Restrict to one relation type (e.g. ``runs-on``).
            max_rows: Row bound for this call.

        Returns:
            ``{'plane': 'declared', 'edges': [DeclaredEdge], 'truncated': bool, 'revision': {...}}``
            — an empty ``edges`` list means the index declares none matching, and
            ``truncated`` says whether the row bound cut the answer.
        """
        budget = self.max_rows if max_rows is None else _bounded('max_rows', max_rows, 1, ROW_CEILING)
        conditions: list[str] = []
        parameters: list[Any] = []
        if relation is not None:
            conditions.append('type = ?')
            parameters.append(_relation(relation))
        with index.readonly(self.index_path) as connection:
            revision = self._revision(connection)
            if resource_id is not None:
                node = _node_id(resource_id)
                self._known(connection, node)
                conditions.append('(source_id = ? OR target_id = ?)')
                parameters += [node, node]
            where = ('WHERE ' + ' AND '.join(conditions) + ' ') if conditions else ''
            rows = connection.execute(
                f'SELECT source_id, type, target_id FROM relations {where}'
                ' ORDER BY source_id, type, target_id LIMIT ?', (*parameters, budget + 1)).fetchall()
        edges = [DeclaredEdge(row['source_id'], row['target_id'], row['type'],
                              revision['declaration_revision'], revision['declaration_sha256'])
                 for row in rows[:budget]]
        return {'plane': DECLARED, 'edges': edges, 'truncated': len(rows) > budget, 'revision': revision}

    def edges_for(self, resource_id: str, *, max_rows: int | None = None) -> dict[str, Any]:
        """Both directions of one resource's declared neighbourhood, in one index open.

        Returns ``depends_on`` (outgoing: what this resource depends on) and
        ``depended_on_by`` (incoming: what depends on it), each an ordered bounded list of
        :class:`DeclaredEdge`, plus the revision. An undeclared id is refused.
        """
        budget = self.max_rows if max_rows is None else _bounded('max_rows', max_rows, 1, ROW_CEILING)
        node = _node_id(resource_id)
        with index.readonly(self.index_path) as connection:
            revision = self._revision(connection)
            self._known(connection, node)
            outgoing, out_cut = self._hop(connection, [node], outgoing=True, budget=budget)
            incoming, in_cut = self._hop(connection, [node], outgoing=False, budget=budget)
        return {'plane': DECLARED, 'resource_id': node, 'revision': revision,
                'depends_on': [self._edge(row, revision) for row in outgoing],
                'depended_on_by': [self._edge(row, revision) for row in incoming],
                'truncated': out_cut or in_cut}

    @staticmethod
    def _edge(row: Any, revision: dict[str, str]) -> DeclaredEdge:
        """The edge as declared (source depends on target), whichever direction was queried."""
        return DeclaredEdge(row['source_id'], row['target_id'], row['relation'],
                            revision['declaration_revision'], revision['declaration_sha256'])

    def _hop(self, connection, frontier: Sequence[str], *, outgoing: bool,
             budget: int) -> tuple[list[Any], bool]:
        """One hop: at most ``budget`` parent/relation/node rows, deterministically ordered.

        The returned flag is the difference between "that was the whole neighbourhood" and
        "the row bound cut it off", so a caller can never report a bounded answer as a
        complete one.
        """
        if budget < 1:
            return [], True
        parent_column, node_column = ('source_id', 'target_id') if outgoing else ('target_id', 'source_id')
        rows: list[Any] = []
        truncated = False
        ordered = sorted(set(frontier))
        for start in range(0, len(ordered), FRONTIER_CHUNK):
            chunk = ordered[start:start + FRONTIER_CHUNK]
            room = budget + 1 - len(rows)
            if room <= 0:
                return rows, True
            placeholders = ', '.join('?' * len(chunk))
            found = connection.execute(
                f'SELECT r.source_id AS source_id, r.type AS relation, r.target_id AS target_id,'
                f' r.{parent_column} AS parent, r.{node_column} AS node, s.kind AS kind, s.name AS name'
                f' FROM relations r'
                f' JOIN resources s ON s.id = r.{node_column}'
                f' WHERE r.{parent_column} IN ({placeholders})'
                f' ORDER BY r.type, r.{parent_column}, r.{node_column} LIMIT ?', (*chunk, room)).fetchall()
            rows.extend(found)
            if len(found) >= room:
                truncated = True
                break
        return rows[:budget], truncated

    def _walk(self, start: str, *, outgoing: bool, direction: str, depth: int,
              max_rows: int) -> dict[str, Any]:
        """BFS with a visited-set guard: terminates on cycles, never returns the start node.

        Two different stops are reported separately. ``'rows'`` means the row/node bound cut the
        answer; ``'depth'`` means the hop bound stopped the walk **and** the next hop would have
        reached a node this call had not already reported. A walk that reached the depth bound on a
        frontier of leaves and already-visited nodes stopped *at* a boundary without being cut by
        it, and says so.
        """
        with index.readonly(self.index_path) as connection:
            revision = self._revision(connection)
            origin = self._known(connection, start)
            visited: dict[str, dict[str, Any]] = {}
            frontier = [start]
            level = 0
            reasons: list[str] = []
            while frontier and level < depth:
                level += 1
                hop, cut = self._hop(connection, frontier, outgoing=outgoing, budget=max_rows)
                if cut:
                    _mark(reasons, 'rows')
                next_frontier: list[str] = []
                for row in hop:
                    node = row['node']
                    if node == start or node in visited:
                        continue
                    if len(visited) >= max_rows:
                        _mark(reasons, 'rows')
                        break
                    visited[node] = {'resource_id': node, 'kind': row['kind'], 'name': row['name'],
                                     'depth': level, 'via': row['parent'], 'relation': row['relation'],
                                     'declaration_revision': revision['declaration_revision']}
                    next_frontier.append(node)
                frontier = sorted(set(next_frontier))
            if frontier and level >= depth and _has_unexplored(
                    connection, frontier, outgoing=outgoing, exclude=set(visited) | {start}):
                _mark(reasons, 'depth')
        nodes = [visited[key] for key in sorted(visited, key=lambda key: (visited[key]['depth'], key))]
        return {'plane': DECLARED, 'direction': direction, 'resource_id': origin['resource_id'],
                'origin_name': origin['name'], 'depth_limit': depth,
                'depth_reached': max((node['depth'] for node in nodes), default=0),
                'nodes': nodes, 'truncated': bool(reasons), 'truncated_by': list(reasons),
                'revision': revision}

    def upstream(self, resource_id: str, depth: int | None = None, *,
                 max_rows: int | None = None) -> dict[str, Any]:
        """Everything ``resource_id`` transitively depends on (outgoing depends-on edges).

        ``depth`` is in hops (1 = direct dependencies). The start node is never among the
        nodes, even on a declared cycle. An undeclared id is refused.

        ``truncated_by`` tells the two ways the answer can be short of the truth: ``'rows'`` (the
        row/node bound cut a hop) and ``'depth'`` (the hop bound stopped the walk while an
        unexplored edge was still waiting one hop out). ``impact`` says the same thing about the
        other direction.
        """
        return self._walk(self._checked(resource_id), outgoing=True, direction='depends-on',
                          depth=self._depth(depth), max_rows=self._rows(max_rows))

    def impact(self, resource_id: str, depth: int | None = None, *,
               max_rows: int | None = None) -> dict[str, Any]:
        """Everything that transitively depends on ``resource_id`` — what breaks if it breaks.

        Same shape and same ``truncated_by`` rules as :meth:`upstream`, in the incoming direction.
        """
        return self._walk(self._checked(resource_id), outgoing=False, direction='depended-on-by',
                          depth=self._depth(depth), max_rows=self._rows(max_rows))

    def _checked(self, resource_id: str) -> str:
        return _node_id(resource_id)

    def _depth(self, depth: int | None) -> int:
        return self.depth if depth is None else _bounded('depth', depth, 1, MAX_DEPTH)

    def _rows(self, max_rows: int | None) -> int:
        return self.max_rows if max_rows is None else _bounded('max_rows', max_rows, 1, ROW_CEILING)

    def shortest_path(self, a: str, b: str, depth: int | None = None) -> dict[str, Any]:
        """Shortest declared depends-on path from ``a`` to ``b``, by BFS, bounded by ``depth``.

        Returns ``status``:

        * ``found`` — ``path`` is ``[a, ..., b]`` (``[a]`` when ``a == b``, which makes no claim
          about an edge, exactly as v0.1 did) and ``edges`` labels each hop with its relation type
          and declaration revision. Every level before the one that reached ``b`` was scanned
          without a cut, which is what licenses the word *shortest*;
        * ``absent`` — the search closed on its own inside the bound, with no cut anywhere in it,
          and ``b`` is not reachable from ``a`` in the depends-on direction. This is an answer, not
          a shrug;
        * ``depth_exceeded`` — the hop bound was reached with an edge still unexplored beyond the
          frontier, so no claim is made either way. ``path`` is empty;
        * ``incomplete`` — a row or discovered-node bound cut one of the levels, so the search
          cannot say *absent* (the missing rows might have led to ``b``) and cannot say *shortest*
          (they might have led there sooner). ``path`` is empty even if a longer route was seen.

        Only ``found`` and ``absent`` carry ``complete: True``, and the cut that decides it is
        cumulative over the whole search, never per hop: a level whose rows ran out is remembered
        even when a later frontier happens to close by itself. Row exhaustion and depth exhaustion
        stay distinguishable — ``truncated_by`` holds ``'rows'``/``'nodes'`` for the first and
        ``'depth'`` for the second.

        An undeclared ``a`` or ``b`` is refused. Ties are broken by sorted neighbour order, so the
        path returned for a given index is stable.
        """
        start, finish = _node_id(a, what='path start'), _node_id(b, what='path target')
        limit = self._depth(depth)
        with index.readonly(self.index_path) as connection:
            revision = self._revision(connection)
            self._known(connection, start)
            self._known(connection, finish)
            if start == finish:
                return self._path('found', start, finish, [start], [], 0, revision)
            parents: dict[str, tuple[str, str]] = {}
            frontier = [start]
            level = 0
            reasons: list[str] = []
            cut_level: int | None = None
            rows_read = 0
            found_level: int | None = None
            while frontier and level < limit:
                level += 1
                room = min(ROW_CEILING, MAX_SEARCH_ROWS - rows_read)
                if room < 1:
                    _mark(reasons, 'rows')
                    cut_level = level if cut_level is None else cut_level
                    break
                hop, cut = self._hop(connection, frontier, outgoing=True, budget=room)
                rows_read += len(hop)
                if cut:
                    _mark(reasons, 'rows')
                    cut_level = level if cut_level is None else cut_level
                next_frontier: list[str] = []
                exhausted = False
                for row in hop:
                    node = row['node']
                    if node == start or node in parents:
                        continue
                    if len(parents) >= MAX_SEARCH_NODES:
                        _mark(reasons, 'nodes')
                        cut_level = level if cut_level is None else cut_level
                        exhausted = True
                        break
                    parents[node] = (row['parent'], row['relation'])
                    if node == finish:
                        found_level = level
                        break
                    next_frontier.append(node)
                if found_level is not None:
                    break
                if exhausted:
                    frontier = []
                    break
                frontier = sorted(set(next_frontier))
            if found_level is not None and (cut_level is None or cut_level >= found_level):
                # Nothing before this level was missed, so no shorter path exists. A cut *at* this
                # level hides other paths of the same length, never a shorter one, and is still
                # reported in truncated_by.
                path = [finish]
                while path[-1] != start:
                    path.append(parents[path[-1]][0])
                path.reverse()
                edges = [DeclaredEdge(path[step], path[step + 1], parents[path[step + 1]][1],
                                      revision['declaration_revision'], revision['declaration_sha256'])
                         for step in range(len(path) - 1)]
                return self._path('found', start, finish, path, edges, found_level, revision, reasons)
            if found_level is not None or reasons:
                # A path may have been seen, but an earlier level was cut: claiming either the
                # absence or the length of a path from a partial graph is the lie this guards.
                return self._path('incomplete', start, finish, [], [], level, revision, reasons)
            if frontier and _has_unexplored(connection, frontier, outgoing=True,
                                            exclude=set(parents) | {start}):
                return self._path('depth_exceeded', start, finish, [], [], level, revision, ['depth'])
            return self._path('absent', start, finish, [], [], level, revision)

    @staticmethod
    def _path(status: str, start: str, finish: str, path: list[str], edges: list[DeclaredEdge],
              depth: int, revision: dict[str, str],
              reasons: Sequence[str] = ()) -> dict[str, Any]:
        """One shape for every ``shortest_path`` outcome, so no branch can forget a key."""
        marks = sorted(set(reasons))
        return {'plane': DECLARED, 'status': status, 'from': start, 'to': finish, 'path': path,
                'edges': edges, 'depth': depth, 'complete': status in ('found', 'absent'),
                'truncated': bool(marks), 'truncated_by': marks, 'revision': revision}

    # -- cycles ------------------------------------------------------------

    def detect_cycles(self, *, limit: int = MAX_CYCLES) -> dict[str, Any]:
        """Declared dependency cycles, reported as DFS witnesses — never traversed infinitely.

        Iterative DFS (explicit stack, no recursion), ported from v0.1. Each reported cycle is the
        node sequence ``[n0, n1, ..., nk]`` meaning ``n0 -> n1 -> ... -> nk -> n0``, found as a
        back-edge onto the current DFS path, rotated to start at its smallest id and reported once.
        A self-relation ``a -> a`` is a cycle of one node.

        What this scan does and does not claim, stated exactly because ``suppression``/``correlation`` read it:

        * **absence is proved**. If ``complete`` is True and ``cycles`` is empty, the declared graph
          is acyclic: a DFS that colours every node and finds no back-edge cannot exist on a graph
          that has a cycle, and ``complete`` means every edge and node of the index took part.
        * **presence is witnessed, not enumerated**. A non-empty list is a set of cycles that
          exist, one per back-edge of *this* DFS forest; a graph can hold further elementary cycles
          that this traversal never walks (a second back-edge can become a tree edge under the
          sorted-DFS order — ``test_a_dfs_witness_list_is_not_an_enumeration`` pins the case). So
          ``count`` is never "the number of cycles in the graph", and reporting a subset does not
          mean the rest are absent.
        * ``limit`` cuts the witness list itself, which is why it sets ``truncated`` and
          ``complete: False``: past the bound the scan stops early and does not even colour the
          remaining nodes, so neither claim survives.

        The scan loads the whole edge set, so an index above ``MAX_EDGES`` edges is refused rather
        than partially scanned: a partial scan could not claim ``complete`` at all.

        Returns ``mode='dfs-witness'`` so a consumer can tell which guarantee it is reading.
        """
        cap = _bounded('limit', limit, 1, MAX_CYCLES)
        with index.readonly(self.index_path) as connection:
            revision = self._revision(connection)
            rows = connection.execute('SELECT source_id, type, target_id FROM relations'
                                      ' ORDER BY source_id, type, target_id LIMIT ?',
                                      (MAX_EDGES + 1,)).fetchall()
            if len(rows) > MAX_EDGES:
                raise TopologyRefusal(f'Declared graph holds more than {MAX_EDGES} edges;'
                                      ' a cycle scan that could not see all of them would lie')
        adjacency: dict[str, set[str]] = {}
        nodes: set[str] = set()
        for row in rows:
            adjacency.setdefault(row['source_id'], set()).add(row['target_id'])
            nodes.add(row['source_id'])
            nodes.add(row['target_id'])
        cycles, truncated = _iterative_cycles(adjacency, nodes, cap)
        return {'plane': DECLARED, 'mode': 'dfs-witness', 'cycles': cycles, 'count': len(cycles),
                'truncated': truncated, 'complete': not truncated,
                'edges_scanned': len(rows), 'nodes_scanned': len(nodes), 'revision': revision}

    def cycle_findings(self, *, source: str = 'topology', now: dt.datetime | None = None,
                       window_seconds: int = 60, limit: int = MAX_CYCLES) -> dict[str, Any]:
        """Declared cycles as findings, with canonical ``coverage`` events naming the rule id.

        The builder admits a declared cycle — ``validation.declared`` only refuses a relation
        whose *target* is not declared — so a cycle that reaches a built index has to become
        a visible finding instead of a silently chosen root. One event per cycle, built by
        ``platform.detections.event`` (imported here for read-only use, never extended):

        * ``rule_id`` = ``topology.declared-cycle.<first 16 hex of the cycle digest>``, so a
          re-run of the same cycle on the same window folds into one condition and a
          different cycle does not;
        * ``resource_id`` = the cycle's smallest node id (the rotation anchor), so the
          incident lands on a declared resource rather than on nothing;
        * evidence = ``query_type='observed-snapshot'`` with ``resource_id`` plus
          ``artifact_sha256`` set to the index's ``declaration_sha256`` — the artifact a
          reviewer can re-read. No evidence *sample* is posted, so ``Store.get_evidence``
          answers ``unavailable`` for it, exactly as the drift producer's does.

        Resolution is not asserted here: this module holds no state, so a cycle that leaves
        the declaration stops firing rather than opening a ``resolved`` event. Full cycle
        membership rides only in the rule id's digest; the node list is re-derived with
        ``detect_cycles()`` against the index whose ``declaration_sha256`` the evidence names.

        Returns the scan plus the events: ``{'cycles', 'complete', 'truncated', 'events',
        'status', 'revision'}`` where ``status`` is ``clean`` or ``finding`` — an empty ``events``
        list is always the result of a complete scan, and it means the declared graph is acyclic.
        A non-empty list is a set of witnesses, not every cycle the graph holds (see
        :meth:`detect_cycles`), so ``finding`` means "this declaration loops", never "these are all
        the loops"; when ``truncated`` is True the events are only the first ``limit`` witnesses.
        """
        from .platform import detections      # read-only use of the event factory (event vocabulary)

        seconds = _bounded('window_seconds', window_seconds, 1, 3600)
        moment = now or dt.datetime.now(dt.timezone.utc)
        if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
            raise TopologyRefusal('Coverage window time must be timezone-aware')
        scan = self.detect_cycles(limit=limit)
        end = dt.datetime.fromtimestamp(int(moment.timestamp()) // seconds * seconds, dt.timezone.utc)
        window = {'start': utc_text(end - dt.timedelta(seconds=seconds)), 'end': utc_text(end)}
        events = []
        for cycle in scan['cycles']:
            digest = hashlib.sha256(canonical(cycle).encode()).hexdigest()
            events.append(detections.event(source, cycle[0], f'{CYCLE_RULE_PREFIX}.{digest[:16]}',
                                           'coverage', 'firing', window,
                                           {'resource_id': cycle[0],
                                            'artifact_sha256': scan['revision']['declaration_sha256']},
                                           query_type=CYCLE_EVIDENCE_QUERY_TYPE))
        return {**scan, 'status': 'finding' if scan['cycles'] else 'clean', 'events': events}


def _iterative_cycles(adjacency: dict[str, set[str]], nodes: Iterable[str],
                      limit: int) -> tuple[list[list[str]], bool]:
    """Port of v0.1's ``detect_cycles``: explicit stack, no recursion, one report per back-edge.

    Returns ``(cycles, truncated)``; ``truncated`` means the report bound was reached, so the
    caller must not describe the list as the whole graph. Even untruncated, the list is a set of
    DFS *witnesses*: colour 1 marks the current path, so a back-edge proves a cycle, and a scan
    that colours every node without one proves there is none — but the white nodes reached first
    fix the DFS tree, and an elementary cycle whose closing edge became a tree/cross edge under
    that order is never emitted. Callers report witnesses and the acyclicity verdict; they do not
    promise the set is every elementary cycle the graph contains.
    """
    color: dict[str, int] = {}        # absent = white, 1 = on the current path, 2 = done
    cycles: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    truncated = False
    for root in sorted(nodes):
        if root in color:
            continue
        color[root] = 1
        path = [root]
        stack: list[tuple[str, Any]] = [(root, iter(sorted(adjacency.get(root, ()))))]
        while stack:
            node, neighbours = stack[-1]
            advanced = False
            for neighbour in neighbours:
                state = color.get(neighbour)
                if state is None:
                    color[neighbour] = 1
                    path.append(neighbour)
                    stack.append((neighbour, iter(sorted(adjacency.get(neighbour, ())))))
                    advanced = True
                    break
                if state == 1:            # back-edge onto the current path: a cycle
                    cycle = path[path.index(neighbour):]
                    canonical_cycle = tuple(cycle[cycle.index(min(cycle)):] + cycle[:cycle.index(min(cycle))])
                    if canonical_cycle not in seen:
                        if len(cycles) >= limit:
                            truncated = True
                            break
                        seen.add(canonical_cycle)
                        cycles.append(list(canonical_cycle))
            if truncated:
                break
            if not advanced:
                stack.pop()
                path.pop()
                color[node] = 2
        if truncated:
            break
    return cycles, truncated


# -- the observed plane: inferred relations are observations, never edges ------------------


def inferred_relation_observation(source: str, *, observed_at: dt.datetime, subject_id: str,
                                  target_id: str, relation: str, evidence: Sequence[str],
                                  observation_id: str | None = None,
                                  subject_aliases: Sequence[dict[str, Any]] = ()) -> discovery.Observation:
    """Build the observed-plane record of one inferred relation: ``subject depends on target``.

    This is the whole port of v0.1's span/network collectors' idea — an inference is a
    claim that something was *seen*, so it goes where every other seen thing goes:
    ``discovery.Observation`` → ``discovery.snapshot`` → ``discovery.ingest``. This
    function writes nothing and opens nothing; a caller with a write path seals it, and
    ``observed_edges`` reads it back. The declared graph never sees it.

    The subject is echoed as the observation's ``resource_id`` — the same echo the Docker
    provider does with its own ``local-observe.resource_id`` label — and resolution stays
    the worker's job. The relation word and the target id ride in attributes
    (``inferred_relation``, ``inferred_relation_target``).

    Raises:
        TopologyRefusal: a non-canonical UUID at either end, a relation word outside the
            declared vocabulary, evidence that is not 1..20 non-blank references of at most
            ``MAX_EVIDENCE_CHARS`` characters each (including a bare ``str``, which is one value
            and not a sequence), or a source name the observed plane refuses.
    """
    if not isinstance(source, str) or not discovery.SOURCE_SHAPE.fullmatch(source):
        raise TopologyRefusal('Observation source must be a bounded lowercase name')
    if observed_at.tzinfo is None or observed_at.tzinfo.utcoffset(observed_at) is None:
        raise TopologyRefusal('Observation time must be timezone-aware')
    subject, target = _node_id(subject_id, what='subject id'), _node_id(target_id, what='target id')
    relation = _relation(relation)
    evidence = _evidence(evidence)
    identifier = observation_id or f'inferred:{source}:{subject}:{relation}:{target}'
    if not 1 <= len(identifier) <= 256:
        raise TopologyRefusal('Observation id must be 1..256 characters')
    return discovery.Observation(source=source, observed_at=observed_at, observation_id=identifier,
                                 aliases=[dict(alias) for alias in subject_aliases],
                                 attributes={INFERRED_RELATION: relation, INFERRED_TARGET: target},
                                 evidence=evidence, resource_id=subject)


def observed_edges(observations_path: Path | str, source: str, *, history_limit: int = 2,
                   max_rows: int | None = None, skip_limit: int = 20) -> dict[str, Any]:
    """Read inferred relations back out of the observed plane: newest claim per edge wins.

    Reads through ``discovery.history`` — the existing bounded, read-only observed-plane
    read — and never touches the declared index, so what an inference saw cannot become a
    declared edge. The newest snapshot carrying an ``(subject, relation, target)`` claim is
    the one reported, because history arrives newest-first.

    A record whose endpoints or relation word do not validate, or which carries an inferred
    relation with no usable evidence behind it, is **skipped visibly**: the reason is listed in
    ``skipped`` (bounded by ``skip_limit``) with ``skipped_count`` as the real total, because
    v0.1's rule was that an unusable inference is reported, not quietly dropped. Reasons are fixed
    sentences and never quote the record. Observations that carry no inferred relation at all are
    not inference candidates and are not skipped — they are simply not part of this read.

    Returns ``{'plane': 'observed', 'source', 'edges', 'truncated', 'skipped',
    'skipped_count', 'snapshots_read', 'newest_observed_at', 'history_complete'}`` where
    ``newest_observed_at`` is the ``observed_at`` of the newest edge actually reported
    (``None`` when nothing was), and ``history_complete`` is False when the number of
    snapshots read reached ``history_limit``. The ``revision`` key is deliberately absent:
    there is no declaration behind an inference.
    """
    if not isinstance(source, str) or not discovery.SOURCE_SHAPE.fullmatch(source):
        raise TopologyRefusal('Observation source must be a bounded lowercase name')
    rows = _bounded('history_limit', history_limit, 2, 1000)
    budget = MAX_ROWS if max_rows is None else _bounded('max_rows', max_rows, 1, ROW_CEILING)
    cap = _bounded('skip_limit', skip_limit, 0, 100)
    snapshots = discovery.history(observations_path, source, limit=rows)
    edges: dict[tuple[str, str, str], ObservedEdge] = {}
    skipped: list[str] = []
    skipped_count = 0
    truncated = False
    for document in snapshots:
        observed_at = str(document.get('observed_at') or '')
        snapshot_id = str(document.get('snapshot_id') or '')
        for item in document.get('observations') or ():
            attributes = item.get('attributes') or {}
            if INFERRED_RELATION not in attributes and INFERRED_TARGET not in attributes:
                continue
            reason = _inference_problem(attributes, item)
            if reason:
                skipped_count += 1
                if len(skipped) < cap:
                    skipped.append(f'{item.get("observation_id", "?")}: {reason}')
                continue
            edge = ObservedEdge(item['resource_id'], attributes[INFERRED_TARGET],
                                attributes[INFERRED_RELATION], source, observed_at, snapshot_id,
                                tuple(item.get('evidence') or ()))
            key = (edge.source_id, edge.relation, edge.target_id)
            if key in edges:
                continue
            if len(edges) >= budget:
                truncated = True
                continue
            edges[key] = edge
    reported = [edges[key] for key in sorted(edges, key=lambda key: (-_time_sort_key(edges[key].observed_at), key))]
    return {'plane': OBSERVED, 'source': source, 'edges': reported, 'truncated': truncated,
            'skipped': skipped, 'skipped_count': skipped_count, 'snapshots_read': len(snapshots),
            'newest_observed_at': reported[0].observed_at if reported else None,
            'history_complete': len(snapshots) < rows}


def _time_sort_key(value: str) -> float:
    try:
        return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except (ValueError, AttributeError):
        return 0.0


def _inference_problem(attributes: dict[str, Any], item: dict[str, Any]) -> str | None:
    """Why this observation cannot be read as an edge, or ``None`` when it can.

    The reasons are fixed sentences: none of them quotes the record's own values, because a skip
    reason is returned to callers and an unbounded inference could otherwise put arbitrary text
    (or a credential-shaped blob an observation was never allowed to carry) into a read answer.

    Evidence is checked here and not only in :func:`inferred_relation_observation`: the observed
    schema permits ``evidence: []``, ``discovery.snapshot`` is the only thing that refuses it, and
    ``discovery.ingest`` accepts a hand-built document that never passed through that helper. An
    inferred edge with no evidence behind it is a claim with nothing backing it, so it is skipped
    visibly on the read boundary too.
    """
    subject = item.get('resource_id')
    if not isinstance(subject, str):
        return 'carries an inferred relation but no resource identity to attach it to'
    try:
        _node_id(subject, what='inferred subject id')
    except TopologyRefusal as exc:
        return str(exc)
    if INFERRED_RELATION not in attributes:
        return f'has no {INFERRED_RELATION} attribute'
    try:
        _relation(attributes[INFERRED_RELATION])
    except TopologyRefusal:
        return f'{INFERRED_RELATION} is outside the declared relation vocabulary'
    if INFERRED_TARGET not in attributes:
        return f'has no {INFERRED_TARGET} attribute'
    try:
        _node_id(attributes[INFERRED_TARGET], what='inferred target id')
    except TopologyRefusal as exc:
        return str(exc)
    try:
        _evidence(item.get('evidence'))
    except TopologyRefusal:
        return 'carries an inferred relation with no usable evidence reference behind it'
    return None

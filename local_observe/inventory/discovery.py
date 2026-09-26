"""Append-only observed snapshots and conservative declaration reconciliation.

The provider contract lives here (``Observation``, ``Provider``, ``snapshot``), in the module that
owns the observed plane, because that is the only thing a discovery source may produce. Boundary:
a provider reports what it saw at one instant and holds no write path. It never mints a resource
UUID, never matches an alias, never removes anything and never proposes a declaration — those are
``index.resolve``, ``drift`` and ``propose``, driven by ``worker.py``, and a proposal still needs a
human merge (discovery write policy). A provider that could reach a declaration writer would be a second, unreviewed
source of truth; ``tests/test_discovery_providers.py`` refuses that by reading the provider sources.
"""
from collections.abc import Sequence
import datetime as dt
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Protocol, runtime_checkable
import uuid

from .index import readonly, resolve
from .validation import InvalidInventory, canonical, digest, observed, timestamp, utc_text

APPLICATION_ID = 0x4C4F4F01
MAX_OBSERVATIONS = 10000
SOURCE_SHAPE = re.compile(r'^[a-z][a-z0-9._-]{0,127}$')
ERROR_CODE_SHAPE = SOURCE_SHAPE


@dataclass(frozen=True)
class Observation:
    """One provider's claim about one resource, shaped exactly like a row of the observed plane.

    These fields are the whole vocabulary a source may assert — an identity it observed, the
    instant it observed it, the aliases and attributes it saw, and the evidence it saw them in.
    Nothing in it names a target: no file path, no declaration body, no approval flag, no
    decision, and no UUID the provider chose. ``resource_id`` is not a lookup either: it is a
    label the operator put on the resource, echoed unchanged, and the worker is still the one
    that resolves it (``index.resolve``) and decides what it means.
    """

    source: str
    observed_at: dt.datetime
    observation_id: str
    aliases: tuple[dict[str, Any], ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[str, ...] = ()
    kind: str | None = None
    name: str | None = None
    resource_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return only the observed-plane keys this source is allowed to assert, omitting unset ones."""
        item: dict[str, Any] = {'observation_id': self.observation_id,
                               'aliases': [dict(alias) for alias in self.aliases],
                               'attributes': dict(self.attributes),
                               'evidence': list(self.evidence)}
        for key in ('kind', 'name', 'resource_id'):
            value = getattr(self, key)
            if value is not None:
                item[key] = value
        return item


@runtime_checkable
class Provider(Protocol):
    """The complete surface of a discovery source: report what it saw, seal it, stop there.

    ``observe()`` is the interface — it returns ``Observation`` values and takes no arguments,
    so a source cannot be handed a write target, an index or a database. ``snapshot()`` is the
    same observations sealed by ``snapshot()`` below into the validated document ``ingest``
    appends; it exists only so a source never hand-rolls the envelope, and it adds no authority.
    A provider has no method that writes, deletes, merges or resolves identity.
    """

    def observe(self) -> list[Observation]:
        """Return what this source saw at its bound instant."""
        ...

    def snapshot(self) -> dict[str, Any]:
        """Return those observations as one validated observed-plane document."""
        ...


def snapshot(source: str, observations: Sequence[Observation], *, now: dt.datetime | None = None,
             scope: Sequence[str] = (), complete: bool = False) -> dict[str, Any]:
    """Seal a provider's observations into one validated append-only snapshot document.

    This is the single enforcement point on a provider's output: the document is checked against
    the observed schema and ``validation.observed`` (identity, alias normalisation, clock skew and
    the ban on credential-shaped attributes) before it exists. A source that emits a malformed or
    over-wide observation fails here rather than in the database. ``complete`` is a claim, not a
    courtesy: only a complete snapshot can ever evidence absence, so a partial view says False.
    """
    moment = now or dt.datetime.now(dt.timezone.utc)
    if not SOURCE_SHAPE.fullmatch(source):
        raise InvalidInventory('Snapshot source must be a bounded lowercase name')
    if len(observations) > MAX_OBSERVATIONS:
        raise InvalidInventory(f'Snapshot exceeds the bound of {MAX_OBSERVATIONS} observations')
    for item in observations:
        if item.source != source:
            raise InvalidInventory('Observation source differs from the snapshot source')
        if item.observed_at.tzinfo is None or item.observed_at.tzinfo.utcoffset(item.observed_at) is None:
            raise InvalidInventory('Observation time must be timezone-aware')
        if not item.evidence:
            raise InvalidInventory('Observation carries no evidence')
    observed_at = max((item.observed_at for item in observations), default=moment)
    if observed_at > moment + dt.timedelta(seconds=60):
        raise InvalidInventory('Observation time exceeds the clock-skew allowance')
    document = {'schema_version': 1, 'source': source, 'snapshot_id': str(uuid.uuid4()),
                'observed_at': utc_text(observed_at), 'status': 'ok',
                'complete': bool(complete), 'scope': list(dict.fromkeys(scope)),
                'observations': [item.as_dict() for item in observations]}
    return observed(document, moment)


def error_snapshot(source: str, error_code: str, *, now: dt.datetime | None = None,
                   scope: Sequence[str] = ()) -> dict[str, Any]:
    """Record that a source could not see anything, which is not the same as seeing nothing.

    A failed read is stored as ``status: error`` with ``complete: false`` and no observations, so
    ``drift`` reports the source unavailable and ``ageing`` refuses to conclude. A prober that
    raised would otherwise look exactly like a network of silent hosts.
    """
    moment = now or dt.datetime.now(dt.timezone.utc)
    if not SOURCE_SHAPE.fullmatch(source) or not ERROR_CODE_SHAPE.fullmatch(error_code):
        raise InvalidInventory('Snapshot source and error code must be bounded lowercase names')
    document = {'schema_version': 1, 'source': source, 'snapshot_id': str(uuid.uuid4()),
                'observed_at': utc_text(moment), 'status': 'error', 'error_code': error_code,
                'complete': False, 'scope': list(dict.fromkeys(scope)), 'observations': []}
    return observed(document, moment)


def ingest(path: Path | str, document: dict[str, Any], *,
           now: dt.datetime | None = None) -> dict[str, Any]:
    now = now or dt.datetime.now(dt.timezone.utc)
    observed(document, now)
    path = Path(path)
    if path.is_symlink():
        raise InvalidInventory('Refusing symlink observed database')
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    try:
        application = connection.execute('PRAGMA application_id').fetchone()[0]
        version = connection.execute('PRAGMA user_version').fetchone()[0]
        tables = connection.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        if (application, version) not in ((APPLICATION_ID, 1), (0, 0)) or (application == 0 and tables):
            raise InvalidInventory('Not a supported observed database')
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('PRAGMA synchronous=FULL')
        connection.execute('BEGIN IMMEDIATE')
        with connection:
            connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
            connection.execute('PRAGMA user_version=1')
            connection.execute('''CREATE TABLE IF NOT EXISTS snapshots (
                source TEXT NOT NULL, snapshot_id TEXT NOT NULL, observed_at TEXT NOT NULL,
                received_at TEXT NOT NULL, payload_sha256 TEXT NOT NULL, payload TEXT NOT NULL,
                PRIMARY KEY(source,snapshot_id), UNIQUE(source,observed_at))''')
            fingerprint = digest(document)
            old = connection.execute('SELECT payload_sha256 FROM snapshots WHERE source=? AND snapshot_id=?',
                                     (document['source'], document['snapshot_id'])).fetchone()
            if old:
                if old[0] != fingerprint:
                    raise InvalidInventory('Snapshot replay changed its contents')
                return {'status': 'duplicate', 'snapshot_id': document['snapshot_id']}
            try:
                connection.execute('INSERT INTO snapshots VALUES (?,?,?,?,?,?)',
                    (document['source'], document['snapshot_id'], utc_text(timestamp(document['observed_at'])),
                     utc_text(now), fingerprint, canonical(document)))
            except sqlite3.IntegrityError as exc:
                raise InvalidInventory('Conflicting snapshots at the same source timestamp') from exc
        return {'status': 'inserted', 'snapshot_id': document['snapshot_id']}
    finally:
        connection.close()


def latest(path: Path | str, source: str) -> dict[str, Any] | None:
    connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        if (connection.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                or connection.execute('PRAGMA user_version').fetchone()[0] != 1):
            raise InvalidInventory('Not a supported observed database')
        row = connection.execute(
            'SELECT payload FROM snapshots WHERE source=? ORDER BY observed_at DESC LIMIT 1',
            (source,)).fetchone()
        return json.loads(row[0]) if row else None
    finally:
        connection.close()


def history(path: Path | str, source: str, *, limit: int = 200) -> list[dict[str, Any]]:
    """Read the newest ``limit`` snapshots of one source, newest first; read-only and bounded."""
    if not 2 <= limit <= 1000:
        raise InvalidInventory('Snapshot history limit must be 2..1000 rows')
    connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        if (connection.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                or connection.execute('PRAGMA user_version').fetchone()[0] != 1):
            raise InvalidInventory('Not a supported observed database')
        rows = connection.execute(
            'SELECT payload FROM snapshots WHERE source=? ORDER BY observed_at DESC LIMIT ?',
            (source, limit)).fetchall()
    finally:
        connection.close()
    return [json.loads(row[0]) for row in rows]


def ageing(path: Path | str, source: str, *, now: dt.datetime | None = None,
           max_age_seconds: int = 3600, grace_seconds: int = 86400,
           history_limit: int = 200, max_aged_percent: int = 50) -> dict[str, Any]:
    """Age out what a source stopped seeing, with ``observed_at`` evidence, and remove nothing.

    Ported from v0.1's shared discovery `reconcile` rule, keeping the rule and dropping its write:
    that function marked records decommissioned inside the inventory it owned. Here the observed
    plane is append-only and declarations are human-owned, so this function only reports. It is the
    answer to the half of "stale discovery is not reported as
    absence" (``docs/COMPONENTS.md`` section 5) that ``drift`` cannot cover: ``drift`` compares one
    snapshot against declarations, so a resource that was only ever *observed* — never declared —
    and then stopped appearing leaves no finding at all.

    It refuses rather than guessing, in every case where absence is not provable: no snapshot, a
    failed read, a snapshot older than ``max_age_seconds``, or a newest snapshot that does not
    claim ``complete``. Each of those returns a status and an empty ``aged_out`` instead of a list
    of gone resources, because a source that stopped reporting is not a network of dead hosts.
    Every ``aged_out`` entry carries ``removed: false``: aging is a conclusion with evidence, and
    the row that produced it stays in the database.

    A fourth refusal bounds how much may be concluded at once: at most ``max_aged_percent`` (an
    integer percent of the observations this source has ever been seen to report, floor of one) may
    age in a single round, and a round that would age more returns ``ageing_capped`` with counts and
    an empty ``aged_out`` rather than an arbitrary subset. The case that rule exists for is a prober
    that has quietly died and answers "no" for every address: its snapshot is fresh, successful and
    ``complete``, so it is indistinguishable from an empty network, which is why the round refuses
    instead of concluding.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    if not 1 <= max_age_seconds <= 604800 or not 1 <= grace_seconds <= 604800:
        raise InvalidInventory('Freshness and grace must be 1..604800 seconds')
    if not 1 <= max_aged_percent <= 100:
        raise InvalidInventory('The ageing cap must be 1..100 percent of the known population')
    report: dict[str, Any] = {'schema_version': 1, 'source': source, 'evaluated_at': utc_text(now),
                              'max_age_seconds': max_age_seconds, 'grace_seconds': grace_seconds,
                              'max_aged_percent': max_aged_percent,
                              'aged_out': []}
    snapshots = history(path, source, limit=history_limit)
    if not snapshots:
        return {**report, 'status': 'source_unavailable', 'reason': 'no_snapshot'}
    edge = snapshots[0]
    context = {'snapshot_id': edge['snapshot_id'], 'observed_at': edge['observed_at']}
    age = (now - timestamp(edge['observed_at'])).total_seconds()
    if age < -60 or age > max_age_seconds:
        return {**report, **context, 'status': 'source_stale', 'reason': 'snapshot_stale'}
    if edge['status'] == 'error':
        return {**report, **context, 'status': 'source_unavailable', 'reason': edge.get('error_code')}
    if not edge['complete']:
        return {**report, **context, 'status': 'coverage_incomplete', 'reason': 'newest_snapshot_partial'}
    last_seen: dict[str, dict[str, Any]] = {}
    for row in snapshots:
        if row['status'] != 'ok':
            continue
        for item in row['observations']:
            last_seen.setdefault(item['observation_id'],
                                 {'observed_at': row['observed_at'], 'evidence': list(item['evidence'])})
    edge_at = timestamp(edge['observed_at'])
    candidates: list[dict[str, Any]] = []
    for observation_id, seen in sorted(last_seen.items()):
        silence = (edge_at - timestamp(seen['observed_at'])).total_seconds()
        if silence > grace_seconds:
            candidates.append({'observation_id': observation_id,
                               'last_seen_observed_at': seen['observed_at'],
                               'silent_seconds': int(silence), 'evidence': seen['evidence'],
                               'removed': False})
    # The denominator is what this read history holds, not the provider's plan: the plan is not in
    # the observed plane and ``scope`` carries declared UUIDs, so last_seen is the only honest
    # population. The floor of one keeps a single host that genuinely vanished ageable.
    known = len(last_seen)
    allowed = max(1, known * max_aged_percent // 100)
    counts = {'known_observations': known, 'aged_candidates': len(candidates),
              'allowed_aged': allowed, 'history_truncated': len(snapshots) >= history_limit}
    if len(candidates) > allowed:
        # No identifiers on this path: a list is read as an answer, and this round has none. The
        # snapshots behind it are still readable with discovery.history().
        return {**report, **context, 'status': 'ageing_capped',
                'reason': 'mass_silence_above_cap', **counts}
    report['aged_out'] = candidates
    return {**report, **context, 'status': 'evaluated', **counts}


def drift(index: Path | str, observations: Path | str, sources: Sequence[str], *,
          now: dt.datetime | None = None, max_age_seconds: int = 3600) -> dict[str, Any]:
    now = now or dt.datetime.now(dt.timezone.utc)
    if not sources or not 1 <= max_age_seconds <= 604800:
        raise InvalidInventory('Expected sources and a freshness limit of 1..604800 seconds are required')
    findings = []
    with readonly(index) as connection:
        declaration_hash = connection.execute(
            "SELECT value FROM build_metadata WHERE key='declaration_sha256'").fetchone()[0]
        def emit(kind, source, resource_id=None, **details):
            finding = {'kind': kind, 'source': source, 'resource_id': resource_id, **details}
            finding['finding_id'] = digest({'declaration': declaration_hash, **finding})
            findings.append(finding)
        for source in sorted(set(sources)):
            snapshot = latest(observations, source)
            if snapshot is None:
                emit('source_unavailable', source, reason='no_snapshot')
                continue
            context = {'snapshot_id': snapshot['snapshot_id'], 'observed_at': snapshot['observed_at']}
            age = (now - timestamp(snapshot['observed_at'])).total_seconds()
            if age < -60 or age > max_age_seconds:
                emit('source_stale', source, **context)
                continue
            if snapshot['status'] == 'error':
                emit('source_unavailable', source, reason=snapshot['error_code'], **context)
                continue
            seen, uncertain = set(), False
            for item in snapshot['observations']:
                match = resolve(connection, resource_id=item.get('resource_id'), aliases=item['aliases'])
                detail = {**context, 'observation_id': item['observation_id'], 'evidence': item['evidence']}
                if match['status'] != 'resolved':
                    uncertain = True
                    emit('undeclared' if match['status'] == 'unknown' else 'identity_unresolved', source,
                         resolution=match, **detail)
                    continue
                resource_id = match['resource_id']
                seen.add(resource_id)
                resource = connection.execute('SELECT * FROM resources WHERE id=?', (resource_id,)).fetchone()
                declared_attrs = json.loads(resource['attributes'])
                differences = {}
                for key, value in item['attributes'].items():
                    if key in declared_attrs and canonical(declared_attrs[key]) != canonical(value):
                        differences['attributes.' + key] = {'declared': declared_attrs[key], 'observed': value}
                for key in ('name', 'kind'):
                    if key in item and item[key] != resource[key]:
                        differences[key] = {'declared': resource[key], 'observed': item[key]}
                if differences:
                    emit('changed', source, resource_id, differences=differences, **detail)
            if snapshot['complete'] and not uncertain:
                for resource_id in sorted(set(snapshot['scope']) - seen):
                    if connection.execute('SELECT 1 FROM resources WHERE id=?', (resource_id,)).fetchone():
                        emit('missing', source, resource_id, **context)
                    else:
                        emit('scope_unresolved', source, resource_id, **context)
            elif not snapshot['complete'] or uncertain:
                emit('coverage_incomplete', source, **context)
    return {'schema_version': 1, 'evaluated_at': utc_text(now), 'declaration_sha256': declaration_hash,
            'findings': sorted(findings, key=lambda item: item['finding_id'])}


def propose(index: Path | str, observations: Path | str, source: str, observation_id: str, output: Path | str, *,
            now: dt.datetime | None = None, max_age_seconds: int = 3600) -> dict[str, Any]:
    now = now or dt.datetime.now(dt.timezone.utc)
    if not 1 <= max_age_seconds <= 604800:
        raise InvalidInventory('Freshness limit must be 1..604800 seconds')
    snapshot = latest(observations, source)
    if (not snapshot or snapshot['status'] != 'ok'
            or not -60 <= (now - timestamp(snapshot['observed_at'])).total_seconds() <= max_age_seconds):
        raise InvalidInventory('Proposal requires a fresh successful source snapshot')
    item = next((item for item in snapshot['observations'] if item['observation_id'] == observation_id), None)
    if not item or not item.get('name') or not item.get('kind') or item['kind'] == 'credential-reference':
        raise InvalidInventory('Proposal requires a named, typed observation without credential material')
    with readonly(index) as connection:
        if resolve(connection, resource_id=item.get('resource_id'), aliases=item['aliases'])['status'] != 'unknown':
            raise InvalidInventory('Only unambiguously undeclared aliases can propose a new UUID')
    path = Path(output)
    key = digest({'source': source, 'observation_id': observation_id})
    fingerprint = digest(item)
    if path.exists():
        existing = json.loads(path.read_text())
        if existing.get('proposal_id') != key or existing.get('observation_sha256') != fingerprint:
            raise InvalidInventory('Existing proposal differs; review instead of overwriting')
        return existing
    result = {'schema_version': 1, 'proposal_id': key, 'status': 'needs_review',
              'source': source, 'snapshot_id': snapshot['snapshot_id'], 'observation_sha256': fingerprint,
              'resource': {'id': str(uuid.uuid4()), 'kind': item['kind'], 'name': item['name'],
                           'aliases': item['aliases'], 'attributes': item['attributes'], 'relations': []}}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    return result

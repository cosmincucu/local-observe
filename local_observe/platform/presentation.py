"""Human labels are presentation metadata, never replacements for durable identities."""
from collections.abc import Sequence
from contextlib import closing
import json
from pathlib import Path
import re
import sqlite3
from typing import Any
from uuid import UUID

from local_observe import topology
from local_observe.inventory.index import readonly
from . import correlation
from .state import GROUPING_TABLE, Store, identifier


def text(value: Any, fallback: str) -> str:
    if not isinstance(value, str) or not value.strip():
        return fallback
    label = ' '.join(value.split())
    try:
        UUID(label)
    except ValueError:
        return label[:160]
    return fallback


def resource_info(index_path: Path | str | None, resource_id: str | None,
                  config: dict[str, Any] | None = None) -> dict[str, str]:
    config = config or {}
    result = {'resource_name': 'Unassigned resource', 'host_name': 'Not declared'}
    if not index_path or not resource_id:
        return result
    try:
        with readonly(index_path) as db:
            row = db.execute('SELECT id,name,kind FROM resources WHERE id=?', (resource_id,)).fetchone()
            if not row:
                return {'resource_name': 'Undeclared resource', 'host_name': 'Not declared'}
            names = config.get('resource_names', {})
            result['resource_name'] = text(names.get(row['id'], row['name']), 'Unnamed resource')
            if row['kind'] == 'host':
                result['host_name'] = result['resource_name']
            else:
                hosts = db.execute("SELECT r.id,r.name FROM relations x JOIN resources r ON r.id=x.target_id"
                                   " WHERE x.source_id=? AND x.type='runs-on' AND r.kind='host'"
                                   ' ORDER BY r.name LIMIT 5', (resource_id,)).fetchall()
                if hosts:
                    result['host_name'] = ', '.join(text(names.get(r['id'], r['name']), 'Unnamed host') for r in hosts)
    except (OSError, sqlite3.Error, ValueError):
        result = {'resource_name': 'Inventory unavailable', 'host_name': 'Unknown'}
    return result


#: How far the incident view's topology section reaches, and how many names it may print.
#: One hop and five names is a label, not a graph browser: the bounded traversals themselves are
#: `local_observe/topology.py`, and a wider view is a surface of its own.
TOPOLOGY_DEPTH = 1
TOPOLOGY_NAMES = 5


def dependency_info(index_path: Path | str | None, resource_id: str | None,
                    config: dict[str, Any] | None = None) -> dict[str, str]:
    """One labelled section: what this resource depends on, and what depends on it.

    Declared plane only (``local_observe/topology.py``): an inference observed in a span is not
    something an operator declared, so it is never labelled as if it were. Direction follows the
    module's convention — ``upstream_name`` answers *this resource depends on*, ``downstream_name``
    answers *what depends on this resource*, i.e. what else breaks if it breaks.

    Every fallback is its own sentence, because they are different facts: no index is
    configured, this incident names no resource, the index does not declare that resource, the
    index could not be read, and the resource is declared with nothing on that side of the graph.
    The ``(more; this list is bounded)`` marker names the one bound this cell can hit — the five
    names — and is deliberately not raised by a depth cut, because one hop is what the view asked
    for rather than what the graph has.

    Args:
        index_path: The built inventory index, or ``None`` when this installation has none.
        resource_id: The incident's resource UUID, or ``None`` for a platform-level incident.
        config: Operator display configuration (``resource_names`` overrides).

    Returns:
        ``{'upstream_name': ..., 'downstream_name': ...}`` — labels only, never identifiers.
    """
    config = config or {}
    unavailable = 'Topology unavailable'
    if not index_path:
        return {'upstream_name': 'Topology not configured', 'downstream_name': 'Topology not configured'}
    if not resource_id:
        return {'upstream_name': 'No resource on this incident',
                'downstream_name': 'No resource on this incident'}
    try:
        graph = topology.Topology(index_path, depth=TOPOLOGY_DEPTH, max_rows=TOPOLOGY_NAMES)
        answer = {'upstream': graph.upstream(resource_id, TOPOLOGY_DEPTH, max_rows=TOPOLOGY_NAMES),
                  'downstream': graph.impact(resource_id, TOPOLOGY_DEPTH, max_rows=TOPOLOGY_NAMES)}
    except topology.UndeclaredResource:
        return {'upstream_name': 'Not declared', 'downstream_name': 'Not declared'}
    except (OSError, sqlite3.Error, ValueError):        # a TopologyRefusal is an inventory refusal
        return {'upstream_name': unavailable, 'downstream_name': unavailable}
    names = config.get('resource_names', {})
    blanks = {'upstream': 'Nothing declared above it', 'downstream': 'Nothing declared below it'}
    result = {}
    for side, nodes in (('upstream', answer['upstream']['nodes']),
                        ('downstream', answer['downstream']['nodes'])):
        if not nodes:
            result[f'{side}_name'] = blanks[side]
            continue
        listed = ', '.join(text(names.get(node['resource_id'], node['name']), 'Unnamed resource')
                           for node in nodes)
        # Only a *row* cut means "there were more names for this one cell". A depth cut means
        # there is something further down the graph, which a one-hop label never promises: saying
        # "more" there would tell the operator the list is short when the list is exactly the
        # direct neighbours. Depth is the view's own choice (TOPOLOGY_DEPTH), stated below.
        if 'rows' in answer[side]['truncated_by']:
            listed += ' (more; this list is bounded)'
        result[f'{side}_name'] = listed
    return result


def describe(event: dict[str, Any], index_path: Path | str | None = None,
             config: dict[str, Any] | None = None) -> dict[str, str]:
    config = config or {}
    rule = event.get('rule_id', '')
    kind = event.get('kind', '')
    defaults = {'availability': 'Availability check failed', 'coverage': 'Monitoring data missing',
                'threshold': 'Detection threshold exceeded', 'drift': 'Inventory drift detected',
                'anomaly': 'Value outside its seasonal baseline', 'security': 'Security rule matched'}
    description = config.get('rule_names', {}).get(rule)
    if not description:
        description = defaults.get(kind, 'Platform availability check' if not event.get('resource_id')
                                   else 'Monitoring incident')
    return {'description': text(description, 'Monitoring incident'),
            **resource_info(index_path, event.get('resource_id'), config)}


def delivery_route(db: sqlite3.Connection, outbox_id: str) -> dict | None:
    """Return the durable safety decision recorded for one delivery, or None when there is none.

    Schema v2 keeps this in `notification_suppressions` (a refusal) and `notification_reservations`
    (the slot a send took). A refusal is the decisive fact when both exist, and it is always about the
    human channel: every refusal in `notification_safety.reserve` is raised before that destination is
    ever replaced by a sink. Where an earlier reservation exists, its own route is shown.

    Schema v3 adds why the last attempt did not land — `attempt` and `cause`, the bounded outcome words
    (`state.ATTEMPT_CAUSES`). They are the whole answer to "was the provider down, or did it refuse
    this?", and they are what makes the row's *delivery absence is visible* promise hold for a channel
    nobody can reach, which a bare accepted/failed boolean could not distinguish.
    """
    suppressed = db.execute('SELECT reason FROM notification_suppressions WHERE outbox_id=?', (outbox_id,)).fetchone()
    reserved = db.execute("""SELECT channel,destination,test_window FROM notification_reservations
        WHERE outbox_id=? ORDER BY id DESC LIMIT 1""", (outbox_id,)).fetchone()
    attempt = db.execute('SELECT result,cause FROM notification_attempts WHERE outbox_id=? '
                         'ORDER BY rowid DESC LIMIT 1', (outbox_id,)).fetchone()
    if not suppressed and not reserved and not attempt:
        return None
    detail = ({'channel': reserved[0], 'destination': reserved[1], 'test_window': reserved[2]} if reserved
              else {'channel': None, 'destination': 'human', 'test_window': None})
    if suppressed:
        detail['reason'] = suppressed[0]
    if attempt:
        detail['attempt'], detail['cause'] = attempt[0], attempt[1]
    return detail


#: Members and rationale lines one incident row names. The list on the row is where the bound is stated
#: (`more` counts what was left out) rather than silently shortened: a group's membership is a fact about
#: the incident, and an operator should be able to see the view stopped counting, and at what number.
GROUPING_LINES = 8
#: Ids per read, the `rca.latest_many` precedent: one page of incidents is at most `Store.records`' 100
#: rows, and a chunk bound is what keeps a wider caller inside SQLite's parameter ceiling.
GROUPING_CHUNK = 100


def grouping_info(db: sqlite3.Connection, incident_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    """The grouped members of each incident on one page, with the stored reason each one joined.

    Four reads for the whole page and no per-row query, which is the lesson `cause_info` records: the
    per-row form had no index to use and rescanned a growing table for every row. Two of them are answered by
    an index — `conditions(incident_id)`, created by schema v7, and the new table's own primary key, whose
    autoindex serves the rationale read (which is why that table needed no index of its own); the anchor read
    is answered by `conditions`' v1 primary key on `key`. That read names the incident's anchor, which sits in
    neither of the other tables (an incident is not a member of itself) and would otherwise leave a resolved
    group displayed with its cause missing. The read keyed on `incident_members` is the one that makes a
    *resolved* group still intelligible: a member that recovered detaches its `conditions` row, and without it
    the incident would lose the very members it was grouped for after the first one came back.

    An incident is described only when it is a group: more than one condition points at it, or a rationale
    row says one once. Anything else gets no entry at all, because "nothing was grouped" and "grouping
    never ran here" must not render as the same claim — and `correlation` deliberately pages per condition, so
    most incidents really are one condition and say so.

    Args:
        db: A read-only connection to the platform database, the one `records` already holds.
        incident_ids: The incident ids on the page, each a canonical UUID.

    Returns:
        ``{incident_id: {'members': [...], 'total': n, 'more': n, 'links': n, 'severity': str}}``, absent
        for every incident that is not a group. `severity` is the derived loudness
        (`correlation.group_severity`) or the empty string when a stored member severity sits outside the
        admitted three, which is a corrupt row and not a quiet incident.

    Raises:
        StateError: An id is not a canonical UUID (`state.identifier`), so a caller cannot widen the read
            with arbitrary SQL text.
    """
    out: dict[str, dict[str, Any]] = {}
    ids = [identifier(one) for one in incident_ids]
    for start in range(0, len(ids), GROUPING_CHUNK):
        chunk = ids[start:start + GROUPING_CHUNK]
        if not chunk:
            continue
        marks = ','.join('?' * len(chunk))
        reasons: dict[tuple[str, str], str] = {}
        links: dict[str, int] = {}
        for row in db.execute(f'SELECT incident_id, condition_key, rationale FROM {GROUPING_TABLE}'
                              f' WHERE incident_id IN ({marks})', chunk):
            reasons[(row[0], row[1])] = row[2]
            links[row[0]] = links.get(row[0], 0) + 1
        listed: dict[str, dict[tuple[str, str], dict[str, Any]]] = {}
        for row in db.execute('SELECT i.id, c.key, c.status, e.payload, (c.incident_id = i.id) AS attached'
                              ' FROM incidents i JOIN conditions c ON c.key=i.condition_key'
                              ' JOIN events e ON e.id=c.event_id'
                              f' WHERE i.id IN ({marks})', chunk):
            _add_member(listed, reasons, row, role='opened')
        for row in db.execute('SELECT c.incident_id, c.key, c.status, e.payload, 1 AS attached'
                              ' FROM conditions c JOIN events e ON e.id=c.event_id'
                              f' WHERE c.incident_id IN ({marks}) ORDER BY c.rowid', chunk):
            _add_member(listed, reasons, row, role='member')
        # A member that resolved has detached its own row; the rationale row still names it, so follow the
        # link back to the condition and say `attached: False` rather than dropping the member. Keyed by
        # the *rationale row's* incident, because `c.incident_id` has moved on (or gone null) by then.
        for row in db.execute(f'SELECT m.incident_id, c.key, c.status, e.payload,'
                              ' (c.incident_id = m.incident_id) AS attached'
                              f' FROM {GROUPING_TABLE} m'
                              ' JOIN conditions c ON c.key=m.condition_key'
                              ' JOIN events e ON e.id=c.event_id'
                              f' WHERE m.incident_id IN ({marks}) ORDER BY m.rowid', chunk):
            _add_member(listed, reasons, row, role='member')
        for incident, members in listed.items():
            rows = sorted(members.values(), key=lambda item: (item['role'] != 'opened', item['condition']))
            if len(rows) < 2 and not links.get(incident):
                continue
            try:
                severity = correlation.group_severity(rows)
            except correlation.CorrelationError:
                severity = ''
            out[incident] = {'members': rows[:GROUPING_LINES], 'total': len(rows),
                            'more': max(0, len(rows) - GROUPING_LINES), 'links': links.get(incident, 0),
                            'severity': severity}
    return out


def _add_member(listed: dict[str, dict[tuple[str, str], dict[str, Any]]],
                reasons: dict[tuple[str, str], str], row: Any, *, role: str) -> None:
    """Fold one member row into the page's grouping map, keeping the attached copy of a pair.

    One condition can be *recorded* under one incident and *attached* to another (it resolved, re-fired and
    joined a different group), so the same `(incident, condition)` pair can arrive from more than one read.
    The attached copy wins: it is the current truth, and the `attached` flag is what tells the operator
    which of the two the line describes. An event payload this build cannot read names nothing at all
    rather than naming whatever bytes were stored.

    `role` says which end of the group the row is: `opened` for the condition that created the incident and
    `member` for one that joined it. A group's cause and its symptoms are not the same line, and the
    operator's question — "is this the thing, or a thing next to it?" — is answered by that field alone.
    """
    incident, condition = row[0], row[1]
    try:
        event = json.loads(row[3])
    except (TypeError, ValueError):
        return
    if not isinstance(event, dict):
        return
    pair = (incident, condition)
    seen = listed.setdefault(incident, {})
    if pair in seen and seen[pair]['attached']:
        return
    seen[pair] = {'condition': condition, 'role': role, 'rule_id': event.get('rule_id'),
                  'kind': event.get('kind'), 'resource_id': event.get('resource_id'),
                  'severity': event.get('severity'), 'status': row[2], 'attached': bool(row[4]),
                  'joined': pair in reasons,
                  'rationale': correlation.parse_rationale(reasons.get(pair))}


def group_label(answer: dict[str, Any] | None) -> str:
    """The one line an operator reads about grouping, including the line that says there is none."""
    if not answer:
        return 'One condition on this incident'
    resources = {item.get('resource_id') for item in answer['members'] if item.get('resource_id')}
    total = answer['total']
    line = f"Grouped: {total} condition{'s' if total != 1 else ''}"
    if resources:
        line += f" across {len(resources)} declared resource{'s' if len(resources) != 1 else ''}"
    if answer['links']:
        line += f", {answer['links']} grouping link{'s' if answer['links'] != 1 else ''} on record"
    if answer['more']:
        line += f" (+{answer['more']} more; this view is bounded)"
    if answer['severity']:
        line += f", shown as {answer['severity']}"
    return text(line, 'Grouped conditions')


def owner_info(index_path: Path | str | None,
               resource_ids: Sequence[str | None]) -> dict[str | None, str]:
    """Who the *declaration* says owns each resource, for a whole page, in one read.

    Routing's only source is the declared resource, and the declaration can spell an owner two ways.
    The typed one is `owner`, one bounded string on the resource object (`schemas/declared.json`) which
    `index.py` stores in the `resources.owner` column; a non-empty value there is the answer and is
    printed as written. The other is the free-form `attributes['owner']`, which predates the field and is
    still read so an existing overlay keeps routing while it moves: a label built from it carries the
    deprecation sentence, because the two spellings must not look identical to the operator. An owner
    declared only in `attributes` renders as
    `<name> (declared under attributes — declare it as owner:)`; anything printed bare came from the
    typed field. correlation followups drafted the typed field on its own and withdrew it (2026-09-10): the field, the
    column and this read order landed together in typed inventory records, because a field the built index drops is an
    owner
    declared and never shown.

    A name, a team, a mail address in a string — the declaration spells it, this only reads it back, and
    `text` bounds every label here to one line.

    Every fallback is its own sentence because they are different facts: no index configured, an incident
    that names no resource, a resource the index does not declare, an index that would not open, an owner
    nobody declared, and an owner declared as something that is not a name (the attribute map is an open
    map of scalars, so the old spelling can hold a number or a boolean, and a `true` is nobody's on-call).

    Never an owner inferred from a hostname: an alias is how a resource is *found*, and whoever owns the
    box is a different claim from the box's name.
    """
    asked = [None if one is None else identifier(one) for one in resource_ids]
    wanted = list(dict.fromkeys(asked))
    if not index_path:
        return {one: 'Ownership not configured' for one in wanted}
    deprecated = '(declared under attributes — declare it as owner:)'
    found: dict[str, tuple[Any, Any]] = {}
    try:
        with readonly(index_path) as db:
            for start in range(0, len(asked), GROUPING_CHUNK):
                chunk = [one for one in asked[start:start + GROUPING_CHUNK] if one is not None]
                if not chunk:
                    continue
                marks = ','.join('?' * len(chunk))
                # The `json_valid` guard is the one `state.py`'s v6 index carries for the same reason:
                # `json_extract` raises on text that is not JSON, and one unreadable stored document must
                # cost that row's label, never the page.
                rows = db.execute('SELECT id, owner, CASE WHEN json_valid(attributes) THEN'
                                  " json_extract(attributes,'$.owner') END FROM resources"
                                  f' WHERE id IN ({marks})', chunk)
                for row in rows:
                    found[row[0]] = (row[1], row[2])
    except (OSError, sqlite3.Error, ValueError):
        return {one: 'Ownership unavailable' for one in wanted}
    labels: dict[str | None, str] = {}
    for one in wanted:
        if one is None:
            labels[one] = 'No resource on this incident'
        elif one not in found:
            labels[one] = 'Not declared'
        else:
            typed, in_attributes = found[one]
            if typed is not None:
                labels[one] = text(typed, 'No owner declared')
            elif in_attributes is None or in_attributes == '':
                labels[one] = 'No owner declared'
            elif not isinstance(in_attributes, str):
                labels[one] = 'Declared owner is not a name'
            else:
                name = text(in_attributes, '')
                if not name:
                    # Whitespace-only, the old spelling's blank: the same sentence as no owner at all,
                    # because there is nothing here to move to the typed field either.
                    labels[one] = 'No owner declared'
                else:
                    label = f'{name} {deprecated}'
                    if len(label) > 160:
                        # The bound holds for the whole label, so the name gives way and the sentence that
                        # tells the operator to move the field is never the part cut off.
                        label = f'{name[:160 - len(deprecated) - 1].rstrip()} {deprecated}'
                    labels[one] = label
    return labels


def cause_info(record: Any) -> dict[str, str]:
    """What the rule floor said about this incident, labelled, or nothing at all when it said none.
    Takes the **record** and not a connection, and that is the whole shape of the fix: the read is
    `platform/rca.py::latest_many`, one query for the page, because the per-row form
    (`stored`, one query per incident) had no index to use — `EXPLAIN QUERY PLAN` on that statement says
    `SCAN audit`, over 20 100 rows — so every row of an incidents page rescanned the whole audit table.
    Measured (scratch/measure_cause_read.py, 20 100 audit rows, a 100-incident page, one machine, other
    work running): 43.8 ms per page for the per-row form against 2.5 ms batched, 17.7×, with the
    `presentation.records` call for that page landing at 5 ms afterwards. The scan is the defect; the
    number is what one machine said, and an audit table with a million rows is where it stops being a
    rounding error. The record arrives through `records`, which imports `rca` inside the function for the
    only reason imports inside functions exist here: `rca.py` imports this module, so a module-level
    arrow the other way would be a load-time cycle at service start (the `state.py` → `audit_reader.py`
    precedent).

    Three facts an operator can act on, and nothing else: the leading candidate (with the cost of the
    bound named, because "there were four" is information about the incident), how loudly the floor
    claimed it, and whether a model touched the wording. Returns ``{}`` when there is no record — an
    incident nobody explained must not render as "explained with no cause", which is how a component
    that was never run reads as a component that found nothing.

    Args:
        record: This incident's stored explanation, or ``None`` when it has none. Anything that is not a
            mapping is answered as "no record", because an unreadable record must not render as a cause.

    Returns:
        ``{}`` when there is no record, else the three label keys below.
    """
    if not isinstance(record, dict):
        return {}
    causes = [item for item in record.get('causes') or [] if isinstance(item, str) and item.strip()]
    further = len(causes) - 1
    leading = text(causes[0] if causes else '', 'No candidate cause on record')
    if causes and further > 0:
        leading = text(f'{leading} (+{further} more; the audit holds the set)', 'No candidate cause on record')
    confidence = record.get('confidence') if record.get('confidence') in ('supported', 'indicated',
                                                                         'unknown') else 'unknown'
    basis = {'rules': 'Rule floor only', 'rules+model': 'Rule floor, wording by a model'}.get(
        record.get('source'), 'Rule floor only')
    return {'cause_name': leading, 'cause_confidence': confidence, 'cause_basis': basis}


def records(store: Store, table: str, rows: list[dict[str, Any]], index_path: Path | str | None = None,
            config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    with closing(sqlite3.connect(store.path.resolve().as_uri()+'?mode=ro', uri=True)) as db:
        explanations: dict[str, dict[str, Any]] = {}
        groups: dict[str, dict[str, Any]] = {}
        owners: dict[str | None, str] = {}
        if table == 'incidents' and rows:
            # One read for the page, before the loop: see `cause_info` for what the per-row version of
            # this cost, and `rca.latest_many` for why an unreadable or unknown-schema record arrives as
            # no record rather than as a half-read one.
            from .rca import latest_many                       # cycle note, as above
            explanations = latest_many(db, [row['id'] for row in rows])
            # And the grouping, on the same connection and with the same one-read-per-page rule: which
            # conditions point at each incident, and the rationale row that says why each one joined.
            groups = grouping_info(db, [row['id'] for row in rows])
            # Routing reads the incident's own resource — the anchor's, not a member's — because that is
            # the declaration that opened the incident and the one an operator can act on.
            owners = owner_info(index_path, [row.get('resource_id') for row in rows])
        for row in rows:
            data = json.loads(row.get('payload') or '{}')
            event = data
            if table == 'incidents':
                linked = db.execute('SELECT payload FROM events WHERE id=?', (row['last_event_id'],)).fetchone()
                event = json.loads(linked[0]) if linked else {}
            elif table == 'outbox':
                event = data.get('event', {})
            elif table == 'executions':
                linked = db.execute('SELECT payload FROM actions WHERE id=?', (row['action_id'],)).fetchone()
                data = json.loads(linked[0]) if linked else {}
            display = describe(event, index_path, config)
            if table == 'incidents':
                # One labelled topology section, and only here: an incident is where "is this the
                # cause or a symptom of something else?" gets asked. `describe` stays cheap because
                # the delivery path (Telegram) calls it per message.
                display.update(dependency_info(index_path, event.get('resource_id'), config))
                # And the explanation beside it, absent rather than empty: a component that never ran
                # must not look like one that ran and found nothing. Read once for the whole page above,
                # on the connection this function already opened; no write lock is taken anywhere here.
                display.update(cause_info(explanations.get(row['id'])))
                # Grouping beside the explanation, in the same two shapes the rail already uses: one
                # labelled sentence in `display` (the detail panel spreads it) and the structured list on
                # the row, which is `delivery_safety`'s precedent for a value that is not a label. The
                # rationale stays machine-readable there, because `rca` re-points members from it.
                answer = groups.get(row['id'])
                display['member_name'] = group_label(answer)
                # Routing asks the incident's own resource — the declaration that opened it, which is the
                # one an operator can act on — and not the newest member's, which is a symptom's identity.
                display['owner_name'] = owners.get(row.get('resource_id'), 'Ownership unavailable')
                if answer:
                    row['grouping'] = answer
            if table in ('actions', 'executions'):
                display['description'] = text(
                    re.sub('[-_.]+', ' ', data.get('action', '')).capitalize(), 'Requested action')
                resources = [resource_info(index_path, target, config) for target in data.get('targets', [])]
                if resources:
                    display['resource_name'] = ', '.join(r['resource_name'] for r in resources)
                    display['host_name'] = ', '.join(dict.fromkeys(r['host_name'] for r in resources))
            if table == 'outbox':
                display['delivery_name'] = {'opened': 'Incident alert',
                                            'resolved': 'Recovery notice'}.get(
                    data.get('transition'), 'Incident notification')
                detail = delivery_route(db, row['id'])
                if detail:
                    row['delivery_safety'] = detail
                    if 'reason' in detail:
                        display['delivery_name'] += ' (suppressed: ' + detail['reason'] + ')'
                    elif detail['destination'] in ('synthetic-sink', 'recording-sink'):
                        display['delivery_name'] += ' (recorded locally; no message sent)'
            row['display'] = display
    return rows

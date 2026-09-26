"""The rule floor: what may be the cause, from what is already on record, before any model is asked.

What this unit is. `docs/COMPONENTS.md`'s `rca` row promises "Rule-based RCA and baselines" and says
that with the component disabled "Detection, incidents and notifications still work". This module is
the rule half of that promise and nothing else: it reads what the platform already holds — the
incident's member events, the evidence those events cite, the declared inventory, the `drift` events
`configdrift.py` reports and the `anomaly` events `anomaly.py` learned — and answers *"what are the
candidate causes, and on what?"* with no model, no query of its own, and no write to operational
state except its own explanation record.

Four rules decide the shape of everything here.

1. **The floor runs first, always.** `candidates()` is deterministic and model-free. A model, when one
   is configured at all, is reached only through the injected `generate` callable and only with the
   rule output in front of it: the permitted operations are **rerank and explain**. The ranked cause
   set is built by `candidates()` and never touched afterwards, so a lying model can change the prose
   and nothing else — which is `tests/test_rca_llm_fabrication.py`, not a memory.
2. **The bundle is assembled from evidence, never from a live query it constructs.** Every telemetry
   fact arrives through `platform/query.py::reauthorise`, which reads the platform's own evidence
   table and issues no query. A reference that has aged out is a **gap**, named in the result, and
   nothing here re-reads the store to fill it: a fresh number wearing a dead reference's identity is
   not evidence, it is the erasure of a retention limit (`docs/CONTRACTS.md` §4; query adapter).
3. **Nothing may be cited that is not in the bundle.** `post_validate()` keeps the sentences whose
   claims (uuids, numbers, dotted or underscored names) all appear in the bundle text and discards the
   rest with a `discarded_fabrication` entry naming the unknown claim. This is v0.1's discipline, and
   it runs against the bundle text rather than a whitelist somebody has to maintain.
4. **No quality claim without the corpus.** This file states no precision number and makes no
   accuracy claim: the labelled-corpus gate is `corpus eval`, and until it runs the component is `selected`,
   not validated (`components/control/rca/versions.json`).

What is deliberately **not** here, each with the reason, because every one is a path a later reader
might reach for:

* **no grouping of several conditions into one incident.** `correlation` owns that decision and takes it at
  intake (`platform/correlation.py` through `Store.grouping_admission`, durable in schema v7's
  `incident_members` and in the `events.incident_id` pointer `Store._join_group` moves). This module only
  **reads** what that transaction decided — one bounded read of the incident's own event rows by that
  pointer — and re-deriving it here at read time is the thing §4 forbids: a cause attributed to a
  declaration that has since changed, or to telemetry that has expired (`telemetry retention`).
* **no re-implementation of baselines.** `anomaly.py` is the one estimator (event kinds's "start light"
  mandate). Its event's `window` is the **evaluation** span; the training span never reaches a
  canonical event, so a baseline signal is carried with its evaluation window and the difference is
  stated in the channel note instead of being quietly re-labelled.
* **no HolmesGPT executor.** holmesgpt (and component policy) allow an optional executor behind this boundary;
  `load_config` refuses one that is switched on, because shipping it needs a verified pin for an
  upstream release nobody here has read past its release tag. The seam, the two cheapest shapes and
  their costs are in `components/control/rca/CONTRACT.md`.
* **no storage of model prose.** The durable record holds candidates, rule ids, citations and counts —
  the redacted minimum context. What a model said is not re-published later as if it were a fact.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from local_observe import topology
from local_observe.inventory.validation import canonical, digest, timestamp, utc_text
from local_observe.log import get_logger
from . import correlation, presentation, query, rca_progress
from .state import Actor, Store, identifier, label, require

log = get_logger(__name__)

#: The bundle's channels, in citation order. `similar_past` was declared and empty on purpose in v0.1 and
#: in every build up to the incident evidence index: a channel that pretends past incidents were consulted is the
#: specific
#: lie this component exists to avoid. It is no longer hollow — one bounded, read-only statement reads
#: resolved incidents of this incident's own `(rule_id, resource_id)` — and the reason it stays short is
#: the same reason it stayed empty: nearest-neighbour similarity over history is not what is readable from
#: this file, so the channel carries identifiers and instants and nothing that would let a rule claim a
#: resemblance nobody measured.
CHANNELS = ('members', 'evidence', 'declaration', 'topology', 'neighbours', 'changes', 'baselines',
            'similar_past')
#: Rows per channel. The total is arithmetic and not luck: `sum(MAX_ITEMS.values())` rows of at most
#: `MAX_ITEM_BYTES` each bounds the bundle before anything is read.
MAX_ITEMS: dict[str, int] = {'members': 12, 'evidence': 20, 'declaration': 1, 'topology': 5,
                             'neighbours': 8, 'changes': 8, 'baselines': 8, 'similar_past': 5}
#: Widest single bundle item. An over-wide item is dropped rather than clipped: a citation the reader
#: cannot check is not a shorter citation, it is a wrong one.
MAX_ITEM_BYTES = 1_024
#: `Store.records` refuses a limit outside 1..100, so this is the ceiling of what one round may see —
#: and `capped` is how every read that stopped there says so. It bounds the three *recency* channels
#: (`neighbours`, `changes`, `baselines`); it does not bound membership, which has its own read below.
RECORDS_LIMIT = 100
#: Events one incident's own member read may return. `correlation.MAX_GROUP_MEMBERS` is the writer's
#: ceiling on a group (`Store._join_group` refuses the next join at it) and the condition that *opened*
#: an incident is never stored as a member of itself (the paragraph above `state.GROUPING_TABLE`), so
#: `events.incident_id` cannot hold more members than that count plus the anchor. A read shorter than
#: this is complete; one that reaches it is labelled, and not presented as the whole group.
MAX_MEMBER_ROWS = correlation.MAX_GROUP_MEMBERS + 1
#: SQLite VM instructions that member read may spend before it stops and calls itself incomplete.
#: `escalation_reader.PROGRESS_INSTRUCTIONS` is the precedent and the same order of magnitude. It is no
#: longer the only thing standing between this read and the whole table: schema step 8
#: (`state.EVENTS_INCIDENT_INDEX`, the incident evidence index) indexes `events.incident_id`, so the read seeks
#: instead of
#: scanning and `MAX_MEMBER_ROWS` is the ceiling that normally binds. The budget stays as the second
#: bound, for the case an index cannot serve: a file restored from a pre-v8 copy or one whose
#: `lo-platform migrate` has not run has nothing to seek with, and then this number is what keeps a
#: per-incident read off a table that grows for the life of the file — and what makes the answer read
#: "membership is unknown" instead of merely arriving late. Removing it would make the migration a
#: correctness requirement of this read rather than a cost improvement, which is not what a schema step is.
MEMBER_READ_INSTRUCTIONS = 128_000
#: Instructions the incident-history read may spend. Same shape and same size for the same reason, and it
#: earns its keep differently: step 8 indexes membership, not this question, and `incidents` carries no
#: index on `resource_id`, so the plan SQLite picks for `SIMILAR_SQL` (measured on a migrated v8 file:
#: `SEARCH i USING INDEX escalation_incidents_status (status=?)`, then `SEARCH e USING INDEX
#: sqlite_autoindex_events_1 (id=?)`) walks every resolved incident in the file and looks up each one's
#: resolving event before the rule and resource filters can say anything. The walk grows with how much
#: history this platform has resolved, and this number is the only bound on it. The read is deliberately
#: not tied to that escalation index with `INDEXED BY`: borrowing it opportunistically costs nothing,
#: depending on another component's schema step is a coupling nobody asked for.
SIMILAR_READ_INSTRUCTIONS = 128_000
#: How often SQLite calls the budget callback. Shared by both bounded reads: it is a granularity, not a
#: per-statement policy, and two spellings of 100 would be one more number to keep in step for nothing.
MEMBER_CHECK_INSTRUCTIONS = 100
#: One incident's own events, oldest first, by the pointer `Store.intake` writes and `Store._join_group`
#: moves when a condition joins a group. One bound UUID, one bound row ceiling, no join and no write.
#: The condition needed no new table or column: it is the membership `correlation` already records. The index it
#: runs on arrived at step 8, because the pointer had existed since v1 and nothing had ever indexed it.
MEMBER_SQL = 'SELECT id, incident_id, payload FROM events WHERE incident_id=? ORDER BY rowid LIMIT ?'
#: Resolved incidents opened by the same rule on the same resource, newest filed first, for one incident.
#: Four bounds and no operator-typed text: the incident being explained (so it never cites itself), its
#: resource, its rule, and `MAX_ITEMS['similar_past'] + 1` rows — the one extra row is what tells the
#: channel it is short instead of complete. It joins `events` because a rule id is stored nowhere else:
#: `incidents.last_event_id` is the event that resolved the incident, which `Store.intake` moves once and
#: nothing re-moves after (`_join_group` re-points members between *open* incidents only), so that one row
#: names the incident's subject the way `suppression._firing_resources` and `escalation_reader` read it.
#: The `json_valid` guard is `MIGRATIONS[6]`'s, for the same reason: `json_extract` raises on a payload
#: that is not JSON, and a read that aborts on one historical row reports a broken store where the guarded
#: form reports a row that simply does not match. Nothing here selects a payload: the item fields are the
#: incident's own two instants and two ids, so no stored value can be cited out of a past incident.
SIMILAR_SQL = ('SELECT i.id, i.opened_at, i.updated_at, i.last_event_id FROM incidents i'
               ' JOIN events e ON e.id=i.last_event_id'
               " WHERE i.status='resolved' AND i.id<>? AND i.resource_id=?"
               ' AND (CASE WHEN json_valid(e.payload)'
               " THEN json_extract(e.payload,'$.rule_id') END)=?"
               ' ORDER BY i.rowid DESC LIMIT ?')
#: The stand-in for "undateable sorts first", which is the direction that keeps a malformed timestamp
#: visible at the head of a window rather than dropped off the end of one nobody reads.
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
#: The two kinds that mean "something was measured about this resource, lately", mapped to the channel
#: that carries them. `drift` is `configdrift.py`'s (drift producer), `anomaly` is `anomaly.py`'s (event kinds).
SIGNAL_CHANNELS = {'drift': 'changes', 'anomaly': 'baselines'}
#: The kinds that are findings rather than statements about measurement, and so may name a neighbour as
#: a candidate cause. `coverage` is in the list on purpose: a blind neighbour is a real fact about the
#: bundle, and "the thing above us stopped reporting" is something an operator can act on.
FINDING_KINDS = frozenset({'availability', 'threshold', 'security', 'coverage'})
#: The three answers a candidate may carry, spelled once. `supported` is reserved for a verdict a
#: producer measured and gave its own refusal state to; `indicated` is co-occurrence inside one
#: window, which is not causation and must never read as if it were.
CONFIDENCE = ('supported', 'indicated', 'unknown')
MAX_CANDIDATES = 8
MAX_CITATIONS = 12
MAX_CAUSES = 4
MAX_CAUSE_CHARS = 140
MAX_DISCARDED = 8
#: The explanation record's ceiling and the fixed field set. `audit.detail` is unbounded SQL text, so
#: the bound lives here or nowhere, and a key outside this set is a refusal rather than a bag.
MAX_EXPLANATION_BYTES = 8_192
EXPLANATION_KEYS = frozenset({'schema_version', 'producer', 'confidence', 'rules', 'causes',
                              'citations', 'llm_used', 'degraded_reason', 'gaps', 'bundle_digest',
                              'source'})
EXPLANATION_SCHEMA_VERSION = 1
#: The audit operations this module writes: one, named as a tuple so the README, the contract and a
#: grep agree (`escalation.OPERATIONS` is the precedent).
OPERATIONS = ('rca.explained',)
#: Every reason the model half may say nothing, spelled once. A word outside this tuple is a bug in
#: this file, not a new state an operator gets.
DEGRADED = ('no_rule_floor', 'model_not_configured', 'budget_exhausted', 'model_unavailable',
            'model_malformed')
DATA_CLASSES = ('public', 'internal', 'restricted')
CONFIG_KEYS = frozenset({'max_incidents', 'max_model_calls', 'lookback_seconds', 'data_class',
                         'executor'})
CONFIG_LIMITS: dict[str, tuple[int, int]] = {'max_incidents': (1, 25), 'max_model_calls': (0, 10),
                                             'lookback_seconds': (60, 86_400)}
DEFAULTS: dict[str, Any] = {'max_incidents': 5, 'max_model_calls': 5, 'lookback_seconds': 3_600,
                            'data_class': 'internal', 'executor': None}
MAX_CONFIG_BYTES = 65_536
#: Claim shapes pulled out of model prose: a uuid, a number, or a name carrying a dot, underscore or
#: colon — the shape of every metric and rule id in this product. A hyphen is deliberately not a
#: separator: `rule-floor` is English and not a resource.
UUID_CLAIM = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
NAME_CLAIM = re.compile(r'[A-Za-z][A-Za-z0-9]*(?:[._:][A-Za-z0-9_]+)+')
NUMBER_CLAIM = re.compile(r'\d+(?:[.,]\d+)?')
SENTENCE_SPLIT = re.compile(r'(?<=[.!?])\s+')
FABRICATION = 'discarded_fabrication'
#: The instruction a model is allowed to be given. Fixed text, so the bundle is the only variable part
#: of a prompt and no caller can smuggle an instruction through this module.
INSTRUCTION = ('You are given an incident and the candidate causes a deterministic rule floor already '
               'produced from it. Do not add, remove or rename a cause. Do not state a number, a '
               'resource or a metric that is not in the evidence: any sentence naming one is '
               'discarded before an operator reads it. Answer in prose.')


class RcaError(ValueError):
    """A caller asked for something this module will not do.

    A `ValueError` subclass, which is what the platform CLI already catches: `cli.main`'s one
    `except (ValueError, OSError, KeyError, TypeError, sqlite3.Error)` prints the machine-readable
    `{"status": "error", "error_type": ...}` line and returns 1. No new branch in the CLI, no new exit
    code, and no claim made about an HTTP status this module never touches — `rca` is reached from a
    command and from a test, and from no route.
    """


@dataclass(frozen=True)
class Candidate:
    """One candidate cause: a rule id, an operator-readable line, and the bundle items behind it."""

    rule: str
    cause: str
    confidence: str
    citations: tuple[str, ...]
    resource_id: str | None = None

    def __post_init__(self) -> None:
        """Refuse a candidate that cannot be checked: an unlabelled rule, an unknown word, no citation."""
        label(self.rule)
        if self.confidence not in CONFIDENCE:
            raise RcaError('Candidate confidence is outside the closed vocabulary')
        if not isinstance(self.cause, str) or not self.cause.strip() or len(self.cause) > MAX_CAUSE_CHARS:
            raise RcaError('Candidate cause text is outside its bound')
        if not self.citations or len(self.citations) > MAX_CITATIONS:
            raise RcaError(f'A candidate cause must cite between 1 and {MAX_CITATIONS} bundle items')
        for citation in self.citations:
            label(citation)

    def as_dict(self) -> dict[str, Any]:
        """Return the stored and transmitted form: five fields, citations as a list."""
        return {'rule': self.rule, 'cause': self.cause, 'confidence': self.confidence,
                'citations': list(self.citations), 'resource_id': self.resource_id}


@dataclass(frozen=True)
class Channel:
    """One bounded bundle channel: its items, and what its bound cost."""

    name: str
    items: tuple[dict[str, Any], ...] = ()
    truncated: bool = False
    #: Why the channel is short or empty when it is, in one sentence: `inventory not configured`,
    #: `nothing declared above or below it`, `no member event inside the newest 100 events read`.
    #: Never invented for a channel that found something.
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return the transmitted form of this channel."""
        return {'items': [dict(item) for item in self.items], 'truncated': self.truncated,
                'note': self.note}


# --------------------------------------------------------------------- configuration


def load_config(path: Path | str) -> dict[str, Any]:
    """Return the analysis document validated, or refuse naming the one thing wrong with it.

    "No document at all" is not this function's business — `cli.py` treats an absent `--config` as
    off, the way `conditions`, `pathcheck` and `escalate` treat theirs. A caller that hands a path to
    this function means it, and gets four refusals: over `MAX_CONFIG_BYTES`, not JSON, an unknown key
    or an out-of-range bound, and an `executor` block that asks for the half this component does not
    build.
    """
    document = _read_json(path)
    if not isinstance(document, dict):
        raise RcaError('RCA configuration must be one JSON object')
    unknown = sorted(set(document) - set(CONFIG_KEYS))
    if unknown:
        raise RcaError(f'RCA configuration names unknown keys: {", ".join(unknown)}')
    merged: dict[str, Any] = dict(DEFAULTS)
    merged.update({key: value for key, value in document.items() if value is not None})
    for name, (low, high) in CONFIG_LIMITS.items():
        value = merged[name]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise RcaError(f'RCA configuration {name} must be an integer {low}..{high}')
    if merged['data_class'] not in DATA_CLASSES:
        raise RcaError(f'RCA configuration data_class must be one of {", ".join(DATA_CLASSES)}')
    _check_executor(merged['executor'])
    return merged


def _check_executor(value: Any) -> None:
    """Refuse an enabled executor, and accept only the honest disabled one.

    holmesgpt decided an optional executor may sit behind this boundary and component policy said build it; what this
    repository can ship today is the seam. Accepting `{"enabled": true}` would make a shipped document
    a lie about code that does not exist, so the refusal names the section that holds the two cheapest
    shapes and what each one costs.
    """
    if value is None:
        return
    if not isinstance(value, dict) or set(value) - {'enabled', 'note'}:
        raise RcaError('RCA configuration executor holds unknown fields')
    if value.get('enabled') is not False:
        raise RcaError('RCA executor must be disabled: the optional executor is documented and not '
                       'built (components/control/rca/CONTRACT.md, "The executor seam")')


def _read_json(path: Path | str) -> Any:
    """Read one bounded JSON document, refusing an oversized or non-JSON file without echoing it."""
    raw = Path(path).read_bytes()
    if len(raw) > MAX_CONFIG_BYTES:
        raise RcaError(f'RCA configuration exceeds {MAX_CONFIG_BYTES} bytes')
    try:
        return json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise RcaError('RCA configuration is not JSON') from None


# --------------------------------------------------------------------- the bundle


def bundle(store: Store, incident: Mapping[str, Any], index_path: Path | str | None = None, *,
           lookback_seconds: int = 3_600, now: dt.datetime | None = None) -> dict[str, Any]:
    """Assemble what the platform already holds about one incident: bounded, and honest about the bounds.

    `incident` is one row of `Store.records('incidents')`. The reads, in order: the incident's member
    events by `correlation`'s own pointer (`_incident_events`, which is *not* a page window and so survives an
    incident older than the newest 100 events the platform has filed); what each of their evidence
    references is worth *now* through `query.reauthorise`; the declared resource and one hop of declared
    graph; and the recent `drift`/`anomaly`/firing-finding verdicts on this resource, on a resource one of
    the members names, or on a declared neighbour — those three channels do read the one capped event
    window, because they are statements about *what is happening lately* and their notes say so.

    Nothing here accepts a query, a statement or an endpoint, and no branch issues a telemetry query. The
    only store touched is the platform's own SQLite file; the only telemetry shown is a retained sample
    that has not expired. Expired and missing references leave through ``gaps`` and are absent from the
    text a model is given, so they cannot be cited by anything downstream.

    The last read is the one that reaches outside this incident: `similar_past`, the most recent resolved
    incidents `SIMILAR_SQL` finds for the pair that opened the incident being bundled. It is a second
    budgeted, read-only statement against the same file and it carries incident ids and instants only, so
    it moves no value from a past incident into a present cause claim; `post_validate` needs no change for
    it, because every claim a sentence could make out of those items is a string the bundle text already
    holds.
    """
    incident_id = identifier(incident['id'])
    resource_id = incident.get('resource_id')
    if resource_id is not None:
        resource_id = identifier(resource_id)
    events = store.records('events', RECORDS_LIMIT)
    member_rows, member_gap = _incident_events(store, incident_id)
    members = _members(member_rows, incident_id, index_path, gap=member_gap)
    span = _span(members)
    graph = _neighbours(index_path, resource_id)
    evidence = _evidence(store, member_rows, incident_id, now=now)
    # The resources this incident itself names. Since `correlation` a group spans several of them, and a drift
    # verdict on a member's own resource is a statement about this incident, not noise from a neighbour.
    named = frozenset(item['resource_id'] for item in members.items if item['resource_id'])
    channels = {
        'members': members,
        'evidence': evidence,
        'declaration': _declaration(index_path, resource_id),
        'topology': _topology(graph),
        'neighbours': _findings(events, resource_id, graph, span, lookback_seconds),
        'changes': _signals(events, 'drift', resource_id, graph, span, lookback_seconds, named),
        'baselines': _signals(events, 'anomaly', resource_id, graph, span, lookback_seconds, named),
        'similar_past': _similar_past(store, incident_id=incident_id, rule_id=_opening_rule(member_rows,
                                                                                            resource_id),
                                      resource_id=resource_id),
    }
    gaps = [{'reference': item['id'], 'status': item['status'], 'detail': item['detail']}
            for item in evidence.items if item['status'] != 'available']
    body: dict[str, Any] = {'schema_version': 1, 'incident_id': incident_id, 'resource_id': resource_id,
                            'span': span, 'capped': len(events) >= RECORDS_LIMIT,
                            'channels': {name: channels[name].as_dict() for name in CHANNELS},
                            'gaps': gaps}
    text = canonical({'span': span, 'resource_id': resource_id, 'channels': body['channels'],
                      'gaps': gaps})
    body['text'] = text
    body['bytes'] = len(text.encode())
    body['digest'] = digest(text)
    return body


def moment(value: Any) -> dt.datetime | None:
    """Parse one stored instant for comparison, or ``None`` when it is not an instant at all.

    Needed because the two writers of these strings disagree in shape and not in time:
    `detections.event` carries the producer's own text (`…Z`) while `state.py` stamps `utc_text`
    (`…+00:00`). Compared as text, `Z` sorts above `+`, which would put a change four minutes before a
    finding on the wrong side of it — so every ordering and window test in this module parses first.
    """
    if not isinstance(value, str):
        return None
    try:
        return timestamp(value)
    except ValueError:
        return None


def _channel(name: str, items: list[dict[str, Any]], *, note: str | None = None) -> Channel:
    """Apply one channel's row and width bounds, recording that a bound was reached.

    `truncated` is True when either bound cost an item, because "the window held more" and "one row was
    too wide to show" are the same thing to a reader who is deciding whether the answer is complete.
    """
    kept: list[dict[str, Any]] = []
    truncated = False
    for item in items:
        if len(kept) >= MAX_ITEMS[name] or len(canonical(item).encode()) > MAX_ITEM_BYTES:
            truncated = True
            continue
        kept.append(item)
    return Channel(name, tuple(kept), truncated=truncated, note=note)


def _event(row: Mapping[str, Any]) -> dict[str, Any]:
    """One `events` row's stored JSON as a canonical-looking dict, or ``{}`` when it is neither.

    A row whose payload is not a dict, or is missing the fields every canonical event carries, is
    unread rather than half-read: a bundle item built from a partial event would be cited as if the
    platform understood it.
    """
    try:
        value = json.loads(row.get('payload') or '{}')
    except (TypeError, ValueError):
        return {}
    if not isinstance(value, dict):
        return {}
    return value if {'window', 'rule_id', 'kind', 'status', 'evidence', 'observed_at'} <= set(value) else {}


def _incident_events(store: Store, incident_id: str) -> tuple[list[dict[str, Any]], str | None]:
    """Every event the platform records as belonging to one incident, read-only and bounded: `(rows, gap)`.

    `gap` is ``None`` when the read was whole and one sentence when it was not, so a short member channel
    can tell "this incident has no members on record" apart from "the read could not finish" — the two
    facts this bundle has never been allowed to confuse. Nothing is inferred from a read that was cut
    short: a partial member set would put `_span` on a footing the rows do not support, and every lookback
    and "did the change come first" test downstream is measured from that span.

    Why a statement at all, when `Store.records('events', RECORDS_LIMIT)` already sat here: that read is
    the newest 100 rows of the *whole table*, so on any platform that has filed its 101st event an older
    incident bundled as a memberless one with an empty span and a note admitting it. The bounded escalation history
    removed
    exactly that defect from `escalation.py` ("an incident that had merely aged out of it"), and `correlation`
    made it sharper rather than milder: a grouped incident's members are precisely the rows a busy newest
    edge pushes out of a page window first, and each of them is now part of the one cause claim.
    `events.incident_id` is that membership — written by `Store.intake`, moved by `Store._join_group`,
    never pruned — and reading it needed no new table and no new column; the index it now runs on is schema
    step 8 (`state.EVENTS_INCIDENT_INDEX`, the incident evidence index), which exists for this statement and nothing
    else.

    A deferred `BEGIN` on a `mode=ro` connection and never `Store.transaction`, which takes the write
    lock: `escalation_reader` states the reason, and this runs once per incident inside a round that also
    writes to the same file.
    """
    steps = 0

    def budget() -> int:
        """Stop the read once it has spent its instruction bound; the count is SQLite's own."""
        nonlocal steps
        steps += MEMBER_CHECK_INSTRUCTIONS
        return int(steps > MEMBER_READ_INSTRUCTIONS)

    try:
        with closing(sqlite3.connect(Path(store.path).resolve().as_uri() + '?mode=ro', uri=True,
                                     isolation_level=None, timeout=10)) as connection:
            connection.row_factory = sqlite3.Row
            connection.set_progress_handler(budget, MEMBER_CHECK_INSTRUCTIONS)
            connection.execute('BEGIN')
            rows = [dict(row) for row in connection.execute(MEMBER_SQL,
                                                            (incident_id, MAX_MEMBER_ROWS + 1))]
    except sqlite3.Error:
        if steps > MEMBER_READ_INSTRUCTIONS:
            return [], (f'the member read stopped at its {MEMBER_READ_INSTRUCTIONS}-instruction budget; '
                        'this incident may have members this bundle does not show')
        return [], ('the member read could not open the platform database; membership is unknown, not '
                    'absent')
    if len(rows) > MAX_MEMBER_ROWS:
        # Kept oldest-first on purpose: `rowid` order is filing order, so the condition that opened the
        # incident is inside what survives and only late re-evaluations are the part that is lost.
        return rows[:MAX_MEMBER_ROWS], (f'the platform records more than {MAX_MEMBER_ROWS} events for '
                                        'this incident; these are its oldest, so the span shown may end '
                                        'earlier than the incident really did')
    return rows, None


def _member_note(items: list[dict[str, Any]], rows: list[dict[str, Any]],
                 gap: str | None) -> str | None:
    """Say why the member channel is empty or short, and never imply a bound it did not read.

    Three different silences, three sentences: the read could not finish, the platform records nothing for
    this incident, and the platform records rows whose payload this build cannot read.
    """
    if gap is not None:
        return gap if items else f'{gap}; no member event was readable at all'
    if items:
        return None
    if rows:
        return (f'{len(rows)} member event rows are on record for this incident and none of them is a '
                'payload this build can read')
    return 'the platform records no member event for this incident'


def _members(events: list[dict[str, Any]], incident_id: str,
             index_path: Path | str | None, *, gap: str | None = None) -> Channel:
    """The incident's own events, oldest first, each with its host name — from the durable member read.

    `events` are the rows `_incident_events` returned for this incident and no others; the `incident_id`
    filter stays because it is the property being asserted (a member of another incident never enters
    this bundle), not because the caller can be trusted with it.
    """
    rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for row in events:
        if row.get('incident_id') != incident_id:
            continue
        event = _event(row)
        if event:
            rows.append((row, event))
    rows.sort(key=lambda pair: (moment(pair[1]['window']['end']) or _EPOCH,
                                pair[1]['source_event_id']))
    hosts: dict[str, str] = {}
    items: list[dict[str, Any]] = []
    for index, (row, event) in enumerate(rows):
        resource_id = event.get('resource_id')
        if resource_id not in hosts:
            hosts[resource_id] = presentation.resource_info(index_path, resource_id)['host_name']
        items.append({'id': f'members:{index}', 'event_id': row['id'], 'resource_id': resource_id,
                      'host_name': hosts[resource_id], 'rule_id': event['rule_id'],
                      'kind': event['kind'], 'severity': event['severity'], 'status': event['status'],
                      'observed_at': event['observed_at'], 'window': event['window'],
                      'evidence_refs': len(event['evidence'])})
    note = _member_note(items, events, gap)
    channel = _channel('members', items, note=note)
    if gap is not None or (events and not rows):
        # A member set this build could not complete is a short channel whatever its row bounds say: the
        # second half is rows on record whose payload nothing here can read.
        return Channel('members', channel.items, truncated=True, note=note)
    return channel


def _evidence(store: Store, events: list[dict[str, Any]], incident_id: str, *,
              now: dt.datetime | None) -> Channel:
    """What each member's evidence references is worth now — and nothing more.

    `query.reauthorise` is the only door, so this function cannot reach the telemetry store even by
    accident. An `available` verdict carries the retained sample; every other verdict is kept here as
    a named gap and is absent from the bundle text by construction. The rows it walks are the incident's
    own from `_incident_events`, so an incident outside the newest-100 window cites the evidence its
    members really named instead of citing nothing.
    """
    items: list[dict[str, Any]] = []
    for row in events:
        if row.get('incident_id') != incident_id:
            continue
        event = _event(row)
        if not event:
            continue
        for reference in event['evidence']:
            verdict = query.reauthorise(store, reference, now=now)
            item: dict[str, Any] = {'id': f'evidence:{len(items)}', 'member': row['id'],
                                    'source': reference.get('source'),
                                    'query_type': reference.get('query_type'),
                                    'window': reference.get('window'),
                                    'expires_at': reference.get('expires_at'),
                                    'status': verdict['status'], 'detail': verdict['detail']}
            if verdict['status'] == 'available':
                item['sample'] = verdict['sample']
            items.append(item)
    return _channel('evidence', items)


def _declaration(index_path: Path | str | None, resource_id: str | None) -> Channel:
    """The incident's declared resource, as labels only: `presentation` owns what an id is called."""
    if resource_id is None:
        return _channel('declaration', [], note='this incident names no resource')
    info = presentation.resource_info(index_path, resource_id)
    return _channel('declaration', [{'id': 'declaration:0', 'resource_id': resource_id, **info}])


def _neighbours(index_path: Path | str | None,
                resource_id: str | None) -> dict[str, Any]:
    """One hop of the declared graph both ways, or an honest empty answer naming its reason.

    Returns ``{'upstream': [...], 'downstream': [...], 'note': str | None}``. The keys follow
    `presentation.dependency_info`: `upstream` is what this resource depends on, `downstream` is what
    breaks if it breaks. A failed read never lands as an empty list with no note — "the index could not
    be opened" and "nothing is declared" are different facts, and the second one is a conclusion.
    """
    if not index_path:
        return {'upstream': [], 'downstream': [], 'note': 'inventory index not configured'}
    if resource_id is None:
        return {'upstream': [], 'downstream': [], 'note': 'incident names no resource to place'}
    try:
        graph = topology.Topology(index_path, depth=1, max_rows=MAX_ITEMS['topology'])
        above = graph.upstream(resource_id, 1, max_rows=MAX_ITEMS['topology'])['nodes']
        below = graph.impact(resource_id, 1, max_rows=MAX_ITEMS['topology'])['nodes']
    except topology.UndeclaredResource:
        return {'upstream': [], 'downstream': [], 'note': 'resource is not declared in the index'}
    except (OSError, sqlite3.Error, ValueError) as exc:      # an inventory refusal is a refusal
        log.info('RCA topology read refused', extra={'error_class': type(exc).__name__})
        return {'upstream': [], 'downstream': [], 'note': 'inventory index unreadable'}
    return {'upstream': above, 'downstream': below, 'note': None if above or below else
            'nothing declared above or below it'}


def _topology(graph: Mapping[str, Any]) -> Channel:
    """The declared neighbours as bounded bundle items, one per node, labelled by direction."""
    items: list[dict[str, Any]] = []
    for direction in ('upstream', 'downstream'):
        for node in graph[direction]:
            items.append({'id': f'topology:{len(items)}', 'resource_id': node['resource_id'],
                          'name': node['name'], 'kind': node['kind'], 'direction': direction})
    return _channel('topology', items, note=graph['note'])


def _findings(events: list[dict[str, Any]], resource_id: str | None, graph: Mapping[str, Any],
              span: Mapping[str, str], lookback_seconds: int) -> Channel:
    """Firing findings on a *declared neighbour* of this incident's resource — never on the resource itself.

    Why the channel exists: the condition key carries the resource, so before `correlation` every item in
    `members` named the same one and "something above this is broken too" was unreadable from membership
    alone. This is the narrow way to see it — the same capped event window, filtered to the neighbours the
    declared graph already named, firing rows only. Naming a neighbour as a candidate cause is what a rule
    floor is for; grouping the two conditions into one incident was `correlation`, and has now landed.

    What `correlation` changes here and what it does not: a *grouped* member on another resource may well be a
    declared neighbour, and then one row appears in both `members` and this channel. That duplication is
    kept rather than filtered, for two reasons. `_earliest_upstream_finding` takes its items from this
    channel, so deleting members from it would silence the rule for exactly the groups that rule now has
    the best evidence for; and the two channels answer different questions — `members` says what belongs to
    this incident, this one says what the declared graph puts above it and when it started firing. The
    duplication exists only while the member row is inside the page this channel reads: membership is
    durable now and recency is not, so for an incident the table has moved past, this channel says it found
    nothing while `members` still names the group. That asymmetry is pinned, not asserted.

    The incident's own resource is excluded by identity, not by kind, so nothing here can shadow the
    member channel or double-count this incident's own finding.
    """
    side = {node['resource_id']: direction for direction in ('upstream', 'downstream')
            for node in graph[direction]}
    first = moment(span.get('first'))
    floor = first - dt.timedelta(seconds=lookback_seconds) if first else None
    items: list[dict[str, Any]] = []
    for row in events:
        event = _event(row)
        neighbour = event.get('resource_id')
        if (event.get('kind') not in FINDING_KINDS or event.get('status') != 'firing'
                or neighbour == resource_id or neighbour not in side):
            continue
        observed = moment(event['observed_at']) or moment(event['window'].get('end'))
        if observed is None or (floor is not None and observed < floor):
            continue
        items.append({'event_id': row['id'], 'resource_id': neighbour, 'direction': side[neighbour],
                      'rule_id': event['rule_id'], 'kind': event['kind'], 'severity': event['severity'],
                      'observed_at': utc_text(observed), 'window': event['window']})
    items.sort(key=lambda item: (moment(item['observed_at']), item['rule_id']))
    for index, item in enumerate(items):
        item['id'] = f'neighbours:{index}'
    note = None if items else ('no firing finding on a declared neighbour inside the window read'
                               if span.get('first') else 'no member window to compare against')
    return _channel('neighbours', items, note=note)


def _signals(events: list[dict[str, Any]], kind: str, resource_id: str | None,
             graph: Mapping[str, Any], span: Mapping[str, str], lookback_seconds: int,
             named: frozenset[str] = frozenset()) -> Channel:
    """Recent `drift`/`anomaly` verdicts on this resource, on one a member names, or on a neighbour.

    The related set is the incident's own resource, the resources its member events name (`correlation` lets a
    group span several of them, and a drift report about a member is a statement about this incident) and
    the one hop already in the bundle: an unrelated host's drift is noise, and widening this to
    "everything lately" is what a symptom page is made of. The lookback floor is derived from the
    incident's first member window rather than from "now", so a replay of an old incident reads the same
    signals an online run saw — and for an incident older than the capped window, that set is legitimately
    empty and the note says which of the two it is.
    """
    name = SIGNAL_CHANNELS[kind]
    related = ({resource_id} | named
               | {node['resource_id'] for direction in ('upstream', 'downstream')
                  for node in graph[direction]})
    first = moment(span.get('first'))
    floor = first - dt.timedelta(seconds=lookback_seconds) if first else None
    items: list[dict[str, Any]] = []
    for row in events:
        event = _event(row)
        if event.get('kind') != kind or event.get('resource_id') not in related:
            continue
        observed = moment(event['observed_at']) or moment(event['window'].get('end'))
        if observed is None:
            continue                       # undateable: it can be neither inside nor outside a window
        if floor is not None and observed < floor:
            continue
        items.append({'event_id': row['id'], 'resource_id': event['resource_id'],
                      'rule_id': event['rule_id'], 'severity': event['severity'],
                      'status': event['status'], 'observed_at': utc_text(observed),
                      'window': event['window']})
    items.sort(key=lambda item: (moment(item['observed_at']), item['rule_id']))
    for index, item in enumerate(items):
        # Ids are assigned after the sort, so a citation names the same item in every run over the
        # same bundle: an id that moved with insertion order would make a stored citation a lie.
        item['id'] = f'{name}:{index}'
    note = _signal_note(name, items, span, floor)
    return _channel(name, items, note=note)


def _signal_note(name: str, items: list[dict[str, Any]], span: Mapping[str, str],
                 floor: dt.datetime | None) -> str | None:
    """Say what an empty or present signal channel means, including the span it cannot name."""
    if name == 'baselines' and items:
        return ('the window shown is the evaluation span; the training span never reaches a canonical '
                'event, so no baseline age is claimed here')
    if items:
        return None
    if not span.get('first'):
        return 'no member window to compare against'
    if floor is None:
        return f'no {name} verdict inside the window read'
    return f'no {name} verdict inside the window read (from {utc_text(floor)})'


def _opening_rule(rows: Sequence[dict[str, Any]], resource_id: str | None) -> str | None:
    """The rule that opened this incident, read off the first row filed against it; ``None`` if unknowable.

    `incidents` stores a resource and no rule — a rule id exists only inside an event payload — and the
    pair `similar_past` matches on is the one that *opened* the incident, not any of the ones `correlation` may
    have grouped under it. `rowid` order is filing order, and `Store._join_group` re-points only the event
    its own transaction has just inserted (the newest row there is), so the first row naming this incident
    is an evaluation of the anchor condition and nothing else: its rule is the incident's rule.

    Two shapes are refused rather than approximated, both answering ``None``: a first row this build cannot
    read, and a first row naming a resource the incident does not (a file that contradicts itself).
    Falling back to the oldest *readable* row would borrow a grouped member's rule as this incident's
    subject and then match a history that is not the one being explained.
    """
    if resource_id is None or not rows:
        return None
    event = _event(rows[0])
    if not event or event.get('resource_id') != resource_id:
        return None
    return event['rule_id']


def _similar_past(store: Store, *, incident_id: str, rule_id: str | None,
                  resource_id: str | None) -> Channel:
    """The newest resolved incidents of this incident's own `(rule_id, resource_id)`: ids and instants.

    What this channel may say is narrow by construction — *this rule on this resource has been opened and
    resolved before, most recently at these two instants*. It is **not** a similarity measure: nearest-
    neighbour resemblance over incident history is the second `Blocked-by` `rca` named, nobody here has
    built one and nobody here has a corpus to tune it against (`corpus eval`). No item carries a payload value, a
    severity or a window, so no rule can quote a number out of a past incident and no model is shown one to
    dress up. `post_validate` needs no new clause for the same reason: every field below is a UUID or an
    instant, and both shapes sit in the bundle text, which is the only place a claim may come from.

    The read is `_incident_events`' shape and takes its reasons from there — a deferred `BEGIN` on a
    `mode=ro` connection rather than `Store.transaction`, which would take the write lock inside a round
    that writes to the same file; one instruction budget; and a `gap` sentence whenever the read could not
    finish, so a short channel says "the read stopped" and never "there is no history". An empty channel
    from a whole read keeps its own sentence too: a platform that has resolved nothing and a read that
    could not tell are different facts, which is the same distinction `_member_note` refuses to collapse.
    """
    if resource_id is None:
        return _channel('similar_past', [], note='this incident names no resource, so no past incident '
                                                 'can be matched to it')
    if rule_id is None:
        return _channel('similar_past', [], note='the rule that opened this incident is not readable on '
                                                 'record, so no incident history was matched against it')
    steps = 0

    def budget() -> int:
        """Stop the history read once it has spent its instruction bound; the count is SQLite's own."""
        nonlocal steps
        steps += MEMBER_CHECK_INSTRUCTIONS
        return int(steps > SIMILAR_READ_INSTRUCTIONS)

    try:
        with closing(sqlite3.connect(Path(store.path).resolve().as_uri() + '?mode=ro', uri=True,
                                     isolation_level=None, timeout=10)) as connection:
            connection.row_factory = sqlite3.Row
            connection.set_progress_handler(budget, MEMBER_CHECK_INSTRUCTIONS)
            connection.execute('BEGIN')
            rows = [dict(row) for row in connection.execute(
                SIMILAR_SQL, (incident_id, resource_id, rule_id, MAX_ITEMS['similar_past'] + 1))]
    except sqlite3.Error:
        gap = (f'the incident-history read stopped at its {SIMILAR_READ_INSTRUCTIONS}-instruction budget; '
               'more resolved incidents of this pair may exist than this channel shows'
               if steps > SIMILAR_READ_INSTRUCTIONS else
               'the incident-history read could not open the platform database; past incidents of this '
               'pair are unknown, not absent')
        channel = _channel('similar_past', [], note=gap)
        return Channel('similar_past', channel.items, truncated=True, note=gap)
    items = [{'id': f'similar_past:{index}', 'incident_id': row['id'], 'opened_at': row['opened_at'],
              'resolved_at': row['updated_at'], 'resolving_event_id': row['last_event_id']}
             for index, row in enumerate(rows)]
    return _channel('similar_past', items,
                    note=None if items else 'no resolved incident with this rule and resource is on record')


def _span(members: Channel) -> dict[str, str]:
    """The incident's own span, read off its member events: earliest evaluation end to latest.

    Emptied rather than guessed when no member carries a window this build can date, because every
    lookback and "did the change come first" test downstream reads these two strings.
    """
    ends = [moment(item['window'].get('end')) for item in members.items
            if isinstance(item.get('window'), dict)]
    dated = [value for value in ends if value is not None]
    if not dated:
        return {'first': '', 'last': ''}
    return {'first': utc_text(min(dated)), 'last': utc_text(max(dated))}


# --------------------------------------------------------------------- the rule floor


def _items(body: Mapping[str, Any], name: str) -> list[dict[str, Any]]:
    """One channel's items, read the way every rule reads them."""
    return list(body['channels'][name]['items'])


def _declared(body: Mapping[str, Any]) -> tuple[str, ...]:
    """The declaration channel's citation ids, appended when a rule wants its answer to name a thing."""
    return tuple(item['id'] for item in _items(body, 'declaration'))


def _cause_text(text: str) -> str:
    """Bound display prose before Candidate validation; identities stay intact in cited items."""
    return text if len(text) <= MAX_CAUSE_CHARS else text[:MAX_CAUSE_CHARS - 1] + '\u2026'


def _change_before(body: Mapping[str, Any]) -> list[Candidate]:
    """A change reported at or before the incident's first finding may be the cause; after it, no."""
    span = body['span']
    out: list[Candidate] = []
    firing = [entry for entry in _items(body, 'changes') if entry['status'] == 'firing']
    first = moment(span.get('first'))
    for item in firing[:MAX_CANDIDATES]:
        observed = moment(item['observed_at'])
        if first and observed and observed > first:
            continue
        out.append(Candidate('change-before-finding',
                             _cause_text(f"artifact change reported by {item['rule_id']} "
                                         f"at {item['observed_at']}"),
                             'indicated', (item['id'], *_declared(body)), item['resource_id']))
    return out


def _baseline_break(body: Mapping[str, Any]) -> list[Candidate]:
    """A series outside the band its own history learned is the one measured candidate in the bundle."""
    out: list[Candidate] = []
    firing = [entry for entry in _items(body, 'baselines') if entry['status'] == 'firing']
    for item in firing[:MAX_CANDIDATES]:
        out.append(Candidate('baseline-break',
                             _cause_text(f"{item['rule_id']} left the seasonal band its own series "
                                         f"learned (window ending {item['window']['end']})"),
                             'supported', (item['id'], *_declared(body)), item['resource_id']))
    return out


def _earliest_upstream_finding(body: Mapping[str, Any]) -> list[Candidate]:
    """The earliest upstream finding observed at or before the incident's first dated member.

    Later and downstream findings remain context in the bundle, but neither supports this rule's
    direction and chronology. An undated incident supplies no ordering to assert.
    """
    first = moment(body['span'].get('first'))
    if first is None:
        return []
    above = [item for item in _items(body, 'neighbours')
             if item['direction'] == 'upstream'
             and (observed := moment(item['observed_at'])) is not None and observed <= first]
    if not above:
        return []
    earliest = min(above, key=lambda item: (moment(item['observed_at']), item['rule_id']))
    named = [node for node in _items(body, 'topology') if node['resource_id'] == earliest['resource_id']]
    citation = [earliest['id']] + [node['id'] for node in named[:1]] + list(_declared(body))
    label = named[0]['name'] if named else earliest['resource_id']
    return [Candidate('earliest-upstream-finding',
                      _cause_text(f'{label} was already firing ({earliest["rule_id"]}) '
                                  f'at {earliest["observed_at"]}, above this resource'),
                      'indicated', tuple(citation), earliest['resource_id'])]


def _source_blind(body: Mapping[str, Any]) -> list[Candidate]:
    """A member that says the monitoring itself went blind: the honest candidate is the blindness.

    Reachable from one incident's own members, which is the whole point: a heuristic that needed two
    conditions grouped into one incident ("the host carries both of these") is Half B and belongs to
    `correlation`, so it is not written here as a wish.
    """
    out: list[Candidate] = []
    blind = [item for item in _items(body, 'members')
             if item['kind'] == 'coverage' and item['status'] == 'firing']
    for item in blind[:MAX_CANDIDATES]:
        out.append(Candidate('source-coverage-blind',
                             _cause_text(f"{item['rule_id']} reports its source stopped reporting at "
                                         f"{item['observed_at']}, so absence cannot be told from outage"),
                             'supported', (item['id'], *_declared(body)), item['resource_id']))
    return out


@dataclass(frozen=True)
class Rule:
    """One deterministic candidate-cause heuristic, and the sentence that justifies running it."""

    id: str
    why: str
    judge: Callable[[Mapping[str, Any]], list[Candidate]]

    def __post_init__(self) -> None:
        """Refuse a rule with an unlabelled id, or one that cannot say why it exists.

        The `why` requirement is the point of the dataclass and not a documentation habit: a rule that
        cannot state why it is tuned the way it is gets deleted, not defended. `tests/test_rca_rules.py`
        asserts every rule carries one non-empty sentence starting `why:`.
        """
        label(self.id)
        if not isinstance(self.why, str) or not self.why.strip().startswith('why:'):
            raise RcaError(f'Rule {self.id} must carry a why: sentence')
        if not callable(self.judge):
            raise RcaError(f'Rule {self.id} names no judge')


#: The floor: four deterministic heuristics, in reporting order, each carrying its `why:`. This is the
#: measured-tuning discipline the `detections` rule is built on, applied to cause-hunting instead of
#: to thresholds.
RULES: tuple[Rule, ...] = (
    Rule('change-before-finding',
         'why: a change with a human decision behind it is the cheapest candidate to name first, and '
         'the only signal in the bundle that says somebody did something; it stays `indicated` and '
         'never becomes `supported`, because landing in the same window as a finding is co-occurrence '
         'and not causation.',
         _change_before),
    Rule('baseline-break',
         'why: a band this product computed from the history of the series itself, with an explicit training '
         'floor and its own insufficient-history refusal (`anomaly.py`, event kinds), is the only statement '
         'about what is normal here that this repository may make without a model; it earns '
         '`supported` because the producer refuses rather than guessing when history is too thin.',
         _baseline_break),
    Rule('earliest-upstream-finding',
         'why: the declared graph is an operator statement, so "the thing above this was already on '
         'fire" is a real ordering and not an inference; it stays `indicated` because the declared plane '
         'says what depends on what and never what broke. Naming a neighbour as a candidate rather than '
         'folding it into this finding is deliberate: `correlation` has since landed and may group the two '
         'conditions into one incident, which is why a member of this incident can now also be an '
         'upstream neighbour — and this rule still only indicates, because a group is not a cause either.',
         _earliest_upstream_finding),
    Rule('source-coverage-blind',
         'why: when a member of the incident says its own source stopped reporting, the candidate an '
         'operator can act on is the blindness and not the metric, because absence cannot be told from '
         'outage; it is `supported` because a coverage verdict is measured by the producer that also '
         'files its resolution, and a cross-incident version of this rule ("one host carries both of '
         'these") is Half B and belongs to correlation, so it is not written here as a wish.',
         _source_blind),
)


def candidates(body: Mapping[str, Any]) -> list[Candidate]:
    """Run every rule over one bundle and return the ranked cause set: deterministic, no model.

    Order is rule order, then bundle order. Nothing downstream of this function reorders, adds or
    removes a candidate — that is the property the lying-model regression exists to keep.
    """
    out: list[Candidate] = []
    for rule in RULES:
        for produced in rule.judge(body):
            if len(out) < MAX_CANDIDATES:
                out.append(produced)
    return out


def confidence_of(found: list[Candidate]) -> str:
    """Return the one word the whole answer deserves: the strongest any candidate claimed."""
    if any(item.confidence == 'supported' for item in found):
        return 'supported'
    return 'indicated' if found else 'unknown'


def floor_text(body: Mapping[str, Any], found: list[Candidate]) -> str:
    """Say the floor's answer in prose this module wrote, so a real answer needs no model at all.

    With nothing found the sentence is the honest one: what was read, how many citations went missing,
    and the reason no model was asked.
    """
    counts = ', '.join(f'{name}={len(body["channels"][name]["items"])}' for name in CHANNELS)
    gaps = len(body['gaps'])
    if not found:
        return (f'No candidate cause. The floor read: {counts}. '
                f'{"Evidence gaps: " + str(gaps) + "." if gaps else "No evidence gaps."} '
                'A model would be inventing rather than explaining, so none was asked.')
    return ' '.join(f'{index + 1}. {item.cause} ({item.confidence})'
                    for index, item in enumerate(found)) + (f' Evidence gaps: {gaps}.' if gaps else '')


# --------------------------------------------------------------------- the model seam


def claims(text: str) -> list[str]:
    """Every checkable claim in one piece of prose: uuids, then dotted names, then bare numbers.

    Each tier is cut out of the text before the next one reads it, so the hex segments inside a uuid do
    not come back as invented numbers and turn one fabrication into nine reported claims. A noisy
    discard list is as useless to an operator as a missing one.
    """
    out = list(UUID_CLAIM.findall(text))
    rest = UUID_CLAIM.sub(' ', text)
    names = NAME_CLAIM.findall(rest)
    rest = NAME_CLAIM.sub(' ', rest)
    return [*out, *names, *NUMBER_CLAIM.findall(rest)]


def unknown_claims(text: str, allowed: str) -> list[str]:
    """The claims in *text* that do not appear in *allowed* — the bundle text is the whole authority.

    Substring containment, as v0.1 had it: a uuid, a number or a metric name that is nowhere in the
    bundle was not in the evidence. The direction of the failure is deliberate — an unknown claim costs
    a discarded sentence, never an accepted one.
    """
    return [claim for claim in dict.fromkeys(claims(text)) if claim not in allowed]


def post_validate(reply: str, allowed: str) -> dict[str, Any]:
    """Keep the sentences a bundle can back; discard the rest naming what cost them.

    Returns ``{'text', 'discarded', 'discarded_count'}``. A sentence is never rewritten: repairing a
    fabrication by editing it leaves the model's invented phrasing in front of the operator with only
    the number removed. `discarded_count` is the true count even when `discarded` is capped.
    """
    kept: list[str] = []
    discarded: list[dict[str, Any]] = []
    total = 0
    for sentence in (part.strip() for part in SENTENCE_SPLIT.split(reply) if part.strip()):
        unknown = unknown_claims(sentence, allowed)
        if unknown:
            total += 1
            if len(discarded) < MAX_DISCARDED:
                discarded.append({'claims': unknown[:MAX_CITATIONS], 'code': FABRICATION})
            continue
        kept.append(sentence)
    return {'text': ' '.join(kept), 'discarded': discarded, 'discarded_count': total}


def explain(body: Mapping[str, Any], *, generate: Callable[..., Any] | None = None,
            data_class: str = 'internal', max_model_calls: int = 5,
            now: dt.datetime | None = None) -> dict[str, Any]:
    """Run the floor, then ask a model — only if one was handed in — to explain it. Never raises.

    `generate` is a seam and not an import: the caller passes something shaped like
    `local_observe.ai.client.AiClient.complete` (`instruction`, `data_class`, `evidence` in; a dict
    carrying `display_text` out). This module does not import that package, so a deployment with no
    endpoint has no optional dependency missing — the `ai` row's *If disabled* column is a property of
    the import graph here rather than a runtime branch.

    Three refusals bound the model half, in this order: no candidates means **no call at all** (there
    is nothing to rerank and nothing to explain, and asking anyway is how a model manufactures a
    cause); no callable means the floor answers on its own; and a call that raises, refuses or returns
    no text is reported and then ignored. Every one of those paths still returns the floor's ranked
    candidates, which is the entire point of the ordering.
    """
    if data_class not in DATA_CLASSES:
        raise RcaError(f'Explain data_class must be one of {", ".join(DATA_CLASSES)}')
    found = candidates(body)
    result: dict[str, Any] = {'confidence': confidence_of(found),
                              'candidates': [item.as_dict() for item in found],
                              'llm_used': False, 'degraded_reason': None,
                              'citations': sorted({citation for item in found
                                                   for citation in item.citations}),
                              'explanation': {'text': floor_text(body, found), 'source': 'rules',
                                              'discarded': [],
                                              'rerank': {'requested': False, 'applied': False,
                                                         'reason': RERANK_REASON}}}
    if not found:
        result['degraded_reason'] = 'no_rule_floor'
        log.info('RCA rule floor found no candidate; no model was asked',
                 extra={'incident_id': body['incident_id'], 'reason': 'no_rule_floor'})
        return result
    if generate is None:
        result['degraded_reason'] = 'model_not_configured'
        return result
    if max_model_calls < 1:
        result['degraded_reason'] = 'budget_exhausted'
        return result
    evidence = [item for channel in body['channels'].values() for item in channel['items']]
    try:
        reply = generate(instruction=f'{INSTRUCTION} Rule output: {result["explanation"]["text"]}',
                         data_class=data_class, evidence=evidence, now=now)
    except Exception as exc:  # the floor must survive whatever the optional half does
        result['degraded_reason'] = 'model_unavailable'
        log.warning('RCA model step failed; the rule floor stands alone',
                    extra={'incident_id': body['incident_id'], 'error_class': type(exc).__name__,
                           'reason': 'model_unavailable'})
        return result
    text = _reply_text(reply)
    if text is None:
        result['degraded_reason'] = 'model_malformed'
        log.warning('RCA model answer carried no text; the rule floor stands alone',
                    extra={'incident_id': body['incident_id'], 'reason': 'model_malformed'})
        return result
    checked = post_validate(text, body['text'])
    result['llm_used'] = True
    result['explanation'] = {'text': checked['text'] or result['explanation']['text'],
                             'source': 'rules+model', 'discarded': checked['discarded'],
                             'rerank': {'requested': True, 'applied': False, 'reason': RERANK_REASON}}
    if checked['discarded_count']:
        log.warning('RCA discarded model sentences that cited nothing in the bundle',
                    extra={'incident_id': body['incident_id'], 'discarded': checked['discarded_count'],
                           'code': FABRICATION})
    return result


#: Why a model may explain but not reorder, in one sentence, in the result rather than only here: a
#: reranked answer has to arrive as JSON, and `local_observe/ai/capability.py` forbids a consumer from
#: using a capability its manifest marks `unknown` or `false` — which is the shipped state today.
RERANK_REASON = ('rerank needs a measured json_mode capability: json_mode is a field of '
                 'local_observe/ai/capability.py FIELDS, no manifest has been measured here, and this '
                 'build may not branch on JSON it did not ask for and did not get')


def _reply_text(reply: Any) -> str | None:
    """The one string a model answer may contribute, or ``None`` when it carries none.

    `display_text` before `content`, because remote inference policy's remote label is part of what an operator is
    shown:
    a consumer that reads `content` has deleted the indication the policy asked for.
    """
    if not isinstance(reply, Mapping):
        return None
    for key in ('display_text', 'content'):
        value = reply.get(key)
        if isinstance(value, str) and value.strip():
            return ' '.join(value.split())
    return None


# --------------------------------------------------------------------- the durable record


def explanation_record(source: str, body: Mapping[str, Any], outcome: Mapping[str, Any]) -> dict[str, Any]:
    """The redacted minimum context of one explanation: identities, verdict words and citations.

    *"Telemetry expires and the explanation must not"* (`docs/CONTRACTS.md` §4, quoted by this
    component's brief), so what is kept is whatever survives the loss of every row behind it: which
    rules ran, what they called, the confidence word, whether a model touched the prose, how many
    citations went missing and the digest of the bundle that produced it. No model prose and no sample
    value: the fields are fixed by `EXPLANATION_KEYS`, so a free-text bag is not merely unadvised here
    but unstorable.
    """
    label(source)
    causes = [item['cause'] for item in outcome['candidates']][:MAX_CAUSES]
    detail: dict[str, Any] = {'schema_version': EXPLANATION_SCHEMA_VERSION, 'producer': source,
                              'confidence': outcome['confidence'],
                              'rules': [item['rule'] for item in outcome['candidates']],
                              'causes': [cause[:MAX_CAUSE_CHARS] for cause in causes],
                              'citations': list(outcome['citations'])[:MAX_CITATIONS],
                              'llm_used': bool(outcome['llm_used']),
                              'degraded_reason': outcome['degraded_reason'],
                              'gaps': len(body['gaps']), 'bundle_digest': body['digest'],
                              'source': outcome['explanation']['source']}
    if set(detail) != EXPLANATION_KEYS:
        raise RcaError('Explanation record fields disagree with the fixed key set')
    if len(canonical(detail).encode()) > MAX_EXPLANATION_BYTES:
        # Unreachable by construction — every field above is bounded first — and kept anyway, because a
        # durable writer that cannot state how wide its own row is should not be trusted with the rest.
        raise RcaError(f'Explanation record exceeds {MAX_EXPLANATION_BYTES} bytes')
    return detail


#: One incident's newest stored explanation, and only that: static SQL, one bound parameter.
READ_SQL = ("SELECT detail FROM audit WHERE operation='rca.explained' AND subject=? "
            'ORDER BY sequence DESC LIMIT 1')
#: The same question asked of a whole page. Chunked because an `IN (...)` list is a bound-parameter list
#: and SQLite has a variable limit; 200 is above any page this product serves (`RECORDS_LIMIT`) and far
#: below the point where the parameter list itself becomes the problem.
LATEST_MANY_CHUNK = 200


def latest_many(connection: sqlite3.Connection, incident_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    """The newest explanation for each of many incidents, in one query per chunk of ids.

    This exists because the per-row form has no index to use: `audit` is ordered by `sequence` and is not
    indexed on `operation` or `subject`, so `stored` called once per incident row scans the whole audit
    table once per row — 43.8 ms against 2.5 ms for a 100-row incidents page over a 20 100-row audit
    trail, measured in `scratch/measure_cause_read.py`, which also prints the `SCAN audit` plan. The
    schema change that fixes it properly is an index on `audit`, which belongs to `state migrations` and not to this
    component.

    Rows come back keyed by incident id, and an incident with no readable record is simply absent — the
    caller distinguishes "no explanation" from "unreadable explanation" by not showing a label, which is
    the same answer either way and the honest one. `readable_schema` is applied here so a record from a
    build this reader cannot place never reaches a view.
    """
    out: dict[str, dict[str, Any]] = {}
    ids = [identifier(one) for one in incident_ids]
    for start in range(0, len(ids), LATEST_MANY_CHUNK):
        chunk = ids[start:start + LATEST_MANY_CHUNK]
        if not chunk:
            continue
        marks = ','.join('?' * len(chunk))
        rows = connection.execute(
            'SELECT subject, detail FROM audit WHERE operation=? AND sequence IN '
            f'(SELECT MAX(sequence) FROM audit WHERE operation=? AND subject IN ({marks}) '
            'GROUP BY subject)', (OPERATIONS[0], OPERATIONS[0], *chunk)).fetchall()
        for subject, raw in rows:
            try:
                value = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if isinstance(value, dict) and readable_schema(value):
                out[subject] = value
    return out


def readable_schema(record: Mapping[str, Any]) -> bool:
    """Whether this reader may show a stored explanation at all.

    The version is a floor and not a ceiling: a record written by a newer build that kept the fields
    this view needs (`rules`, `causes`, `confidence`) is still true of the incident it describes, and
    refusing it would erase an explanation because the *viewer* is old. What is refused is a row whose
    version this reader cannot place — absent, a string, a boolean, or below the first published shape
    — because showing that means guessing at a field's meaning, and a guessed field on an incident view
    is indistinguishable from a measured one.
    """
    version = record.get('schema_version')
    return (isinstance(version, int) and not isinstance(version, bool)
            and version >= EXPLANATION_SCHEMA_VERSION)


def stored(connection: sqlite3.Connection, incident_id: str) -> dict[str, Any] | None:
    """Return the newest stored explanation for one incident as written, or ``None``.

    The connection is the caller's, so this reads inside whichever transaction or read view asked for
    it. A `detail` that does not parse back to a mapping, or whose `schema_version` this reader cannot
    place, is reported as no record rather than shown half-read: an explanation nobody can trust is
    worse than a stated gap.
    """
    row = connection.execute(READ_SQL, (incident_id,)).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(row[0])
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict) or not readable_schema(value):
        return None
    return value


def record(store: Store, incident_id: str, detail: Mapping[str, Any], actor: Actor, *,
           now: dt.datetime | None = None) -> dict[str, Any]:
    """File one explanation beside its incident, through the store's own transaction and audit path.

    An append-only `audit` row and not a new table — the choice, and the cost of it, stated once. The
    row is durable, is never pruned, is written by the one writer the platform already has
    (`escalation.py` files its decisions exactly this way) and is readable today through
    `Store.records('audit')` and `GET /v1/audit`. A table of its own needs a `VERSION` bump, a
    migration script and the current-table pin in `tests/test_state_migration.py` moved beside it,
    which is `state migrations`'s mechanism and a reviewer's decision rather than an edit made alongside it.

    Idempotent by content: the newest row for this incident is compared first, so a round that
    re-analyses an unchanged incident writes nothing and answers `unchanged`. Without that, a
    five-minute timer turns one quiet incident into 288 audit rows a day.
    """
    require(actor, 'producer')
    incident_id = identifier(incident_id)
    if not isinstance(detail, Mapping) or set(detail) != EXPLANATION_KEYS:
        raise RcaError('Explanation record fields disagree with the fixed key set')
    moment = now or dt.datetime.now(dt.timezone.utc)
    body = dict(detail)
    with store.transaction() as connection:
        if stored(connection, incident_id) == body:
            return {'recorded': 'unchanged', 'incident_id': incident_id}
        store.audit(connection, moment, actor.identity, OPERATIONS[0], incident_id, body)
    return {'recorded': 'written', 'incident_id': incident_id, 'at': utc_text(moment)}


def read_latest(store: Store, incident_id: str) -> dict[str, Any] | None:
    """One incident's newest explanation, read through the store's transaction helper.

    Takes the store and not a connection because the callers are a CLI and a test; the serving path
    (`presentation.records`) already holds a read-only connection and calls `stored` directly.
    """
    with store.transaction() as connection:
        return stored(connection, identifier(incident_id))


# --------------------------------------------------------------------- the round


def analyze(store: Store, incident: Mapping[str, Any], index_path: Path | str | None = None, *,
            config: Mapping[str, Any] | None = None, source: str = 'rca',
            generate: Callable[..., Any] | None = None,
            now: dt.datetime | None = None) -> dict[str, Any]:
    """Bundle, floor, explain, record: one incident; malformed data and storage errors may refuse it.

    The report carries the answer and the bundle's metrics — bytes, digest, gaps — but not the bundle
    text itself, which is what a model was shown rather than what an operator reads.
    """
    settings = dict(DEFAULTS, **dict(config or {}))
    built = bundle(store, incident, index_path, lookback_seconds=settings['lookback_seconds'], now=now)
    outcome = explain(built, generate=generate, data_class=settings['data_class'],
                      max_model_calls=settings['max_model_calls'], now=now)
    detail = explanation_record(source, built, outcome)
    written = record(store, built['incident_id'], detail, Actor(source, 'producer'), now=now)
    explanation = outcome['explanation']
    report = {key: value for key, value in outcome.items() if key != 'explanation'}
    report.update({'incident_id': built['incident_id'], 'explanation_text': explanation['text'],
                   'explanation_source': explanation['source'], 'discarded': explanation['discarded'],
                   'rerank': explanation['rerank'], 'gaps': built['gaps'],
                   'bundle_bytes': built['bytes'], 'bundle_digest': built['digest'],
                   'recorded': written['recorded']})
    return report


def tick(store: Store, index_path: Path | str | None = None, *, config: Mapping[str, Any],
         source: str, generate: Callable[..., Any] | None = None,
         now: dt.datetime | None = None) -> dict[str, Any]:
    """One durable rotation page over open incidents, bounded by incident and model budgets.

    `max_incidents` caps the incidents one round touches and `max_model_calls` caps the generation
    calls for the whole round. The byte and evidence budget of a *single request* is
    `local_observe/ai/budget.py`'s and is not re-implemented here: this module holds the only budget
    object in the product that counts model calls rather than model bytes (rca task 6), and it says
    `budget_exhausted` when it runs out instead of silently making a smaller round.

    The source's sidecar fixes a cycle high-water and remembers each examined row. Later arrivals wait
    for the next cycle. Known failures are visible per incident and retried in the next cycle, while
    other incidents continue. The page read connection is closed before any analysis writes.
    """
    settings = dict(DEFAULTS, **dict(config))
    label(source)
    for name in ('max_incidents', 'max_model_calls'):
        low, high = CONFIG_LIMITS[name]
        if type(settings[name]) is not int or not low <= settings[name] <= high:
            raise RcaError(f'RCA configuration {name} must be an integer {low}..{high}')
    moment = now or dt.datetime.now(dt.timezone.utc)
    calls_left = settings['max_model_calls']
    reports: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    with rca_progress.Progress(store.path, source) as progress:
        rows, more = progress.page(settings['max_incidents'])
        for row in rows:
            budget = calls_left
            calls_left = max(calls_left - 1, 0)
            try:
                reports.append(analyze(store, row, index_path, config=dict(settings, max_model_calls=budget),
                                       source=source, generate=generate, now=moment))
            except (ValueError, OSError, KeyError, TypeError, sqlite3.Error) as exc:
                failure = {'incident_id': row['id'], 'rowid': row['rowid'],
                           'error_class': type(exc).__name__}
                failures.append(failure)
                log.warning('RCA incident analysis refused; continuing the cycle', extra=failure)
            progress.advance(row['rowid'])
        progress.finish(more)
    return {'status': 'ran', 'source': source, 'incidents_open': len(rows),
            'incidents_read': len(rows) + int(more), 'count_scope': 'page', 'capped': more,
            'cycle_complete': not more, 'attempted': len(rows), 'failed': len(failures),
            'failures': failures,
            'analyzed': len(reports),
            'written': len([item for item in reports if item['recorded'] == 'written']),
            'unchanged': len([item for item in reports if item['recorded'] == 'unchanged']),
            'no_candidate': len([item for item in reports if item['confidence'] == 'unknown']),
            'model_used': len([item for item in reports if item['llm_used']]),
            'discarded': sum(len(item['discarded']) for item in reports), 'results': reports}


#: Every public name, so a reader of `docs/STRUCTURE.md` and a reader of this file agree on the surface.
__all__ = ['CHANNELS', 'CONFIDENCE', 'DEGRADED', 'MAX_ITEMS', 'OPERATIONS', 'Candidate', 'Channel',
           'RcaError', 'Rule', 'RULES', 'analyze', 'bundle', 'candidates', 'claims', 'confidence_of',
           'explain', 'explanation_record', 'floor_text', 'load_config', 'post_validate', 'record',
           'read_latest', 'stored', 'tick', 'unknown_claims']

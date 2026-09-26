"""The grouping rule: when two conditions may become one incident, and the reason that outlives telemetry.

Port of ``legacy:aiops/correlate`` (``signals.py`` 98 lines, the grouping and severity rules of ``engine.py``
188), reduced to what this repository's canonical event can actually carry, and moved off the in-memory
engine: a grouping decided in a process is a grouping that walks away when the process does, and §4
promises an incident can still be understood *after* the telemetry that produced it is gone. So the
judgement stays here, pure, and the durable half lives in `platform/state.py`, whose single writer calls
`link()` inside the transaction that files the event (`Store.grouping_admission`).

THE GROUPING RULE, as an assertible property rather than a comment: a link needs a temporal match **and**
at least one corroborating structural signal. `link()` is the only function that composes signals, it
returns either the whole link or `None`, and it is written so that a caller cannot ask it for the temporal
half alone — the invariant test (`tests/test_correlation.py`) calls `temporal()` on two conditions that
coincide in the same minute and asserts it *does* answer, then calls `link()` on the same pair with an
unrelated graph and asserts it answers `None`. Co-occurrence alone produces one mush-incident per busy
hour, which is not an incident but a histogram.

SIGNALS PORTED, AND THE ONE THAT WAS NOT. `temporal` and `topological` cross; **`label_affinity` does
not**, because the canonical event has no label field at all — `state.validate_event` compares the field
set for equality and refuses an extra key — and inventing one to feed a ported signal would widen §4's
closed event shape for a correlation heuristic. Port table §6 asked for grouping keyed on *declared UUIDs
and the graph*, which is exactly the two signals that survived.

WHY AN EDGE AND NOT "SAME RESOURCE". `topology.shortest_path(x, x)` answers `found` with the one-node
path and the module says plainly that this "makes no claim about an edge". v0.1 scored that 1.0, and here
it would be wrong in a specific and damaging way: `detections.evaluate` files a source-coverage condition
and the underlying finding as two events on the **same resource** in the same window, precisely so that
"the probe could not run" stays visible as its own open condition (§4.2, "coverage does not open the
underlying condition"). Grouping them on identity would let a coverage resolution hold a service's real
outage open — and an outage's resolution close its coverage gap. So `topological` requires one or more
declared hops between two *different* resources.

WHAT A RATIONALE IS. One JSON array per grouping link: for each matched signal its kind, one bounded
sentence, its 0..1 score, and the *references* that corroborate it — the declared path as resource UUIDs
and relation words, and the declaration's digest. Never an event payload, never evidence parameters, never
a value read out of a producer: the sentence is composed here from fixed words and identifiers this module
extracted itself, which is what makes §4's "minimum redacted context" testable rather than a hope. The
bound is `MAX_RATIONALE_CHARS`, asserted before the link is returned (an inexpressible rationale is no
grouping at all, so the event files its own incident and the operator sees two pages instead of one wrong
one) and again in SQL in `state.MIGRATIONS[7]`, so the promise belongs to the file and not to one caller.
"""
from dataclasses import dataclass, field
import datetime as dt
import json
import re
import sqlite3
from typing import Any

from local_observe.inventory.validation import InvalidInventory, canonical, timestamp

from .vocabulary import ADMITTED_SEVERITIES

__all__ = ['CorrelationError', 'Grouping', 'MAX_GROUP_MEMBERS', 'MAX_HOPS', 'MAX_PROMOTION_THRESHOLD',
           'MAX_RATIONALE_CHARS', 'MAX_SEARCH_HOPS', 'MAX_WINDOW_SECONDS', 'PROMOTION_THRESHOLD',
           'RATIONALE_KINDS', 'WINDOW_SECONDS', 'group_severity', 'is_escalation_rung', 'link',
           'parse_rationale', 'promote', 'rationale_document', 'temporal', 'topological']

#: Seconds inside which two conditions may be *considered* one incident. Never the whole claim: the
#: module docstring says why. Ported value, unchanged from `legacy:aiops/correlate/engine.py`.
WINDOW_SECONDS = 300
#: The widest window an installation may ask for. Past an hour, "temporally close" stops describing an
#: outage and starts describing a shift, and every structural signal in the file becomes a coin flip.
MAX_WINDOW_SECONDS = 3600
#: Declared hops a link may cross. Two: a service and the host it runs on, or a service and the volume it
#: depends on. `platform/suppression.py` walks one hop to blame a parent; this asks a wider question and
#: is bounded tighter than `topology.MAX_DEPTH` (10) on purpose — a long path is a chain of excuses.
MAX_HOPS = 2
#: The hop bound `link()`/`topological()` will accept from a caller, and the ceiling of the search this
#: module is allowed to start. Mirrors `suppression.MAX_DEPENDENCY_DEPTH`: past four declared hops the
#: answer "these two are related" costs a graph walk nobody asked for.
MAX_SEARCH_HOPS = 4
#: Distinct resources at which a group is promoted one rank toward critical. Ported value (3): a warning
#: that reaches three subsystems is a different event from a warning on one host.
PROMOTION_THRESHOLD = 3
#: The widest promotion threshold, so a mis-typed configuration cannot buy "never promote" by accident.
MAX_PROMOTION_THRESHOLD = 100
#: Characters one stored rationale may hold. Sized from this module's own worst link (two signals, a
#: three-node path of canonical UUIDs, three relation words, one digest): about 600 characters. The
#: surplus is the bound's cost, not slack for a wider walk — `link()` refuses rather than truncating, and
#: `state.MIGRATIONS[7]` repeats the number in SQL.
MAX_RATIONALE_CHARS = 1024
#: Conditions one incident may hold. A group is a claim about a cause, and a claim that has swallowed a
#: hundred conditions is an outage report with an id; the ceiling is what makes `MAX_RATIONALE_CHARS`
#: per-link also a bound on the whole incident's stored explanation.
MAX_GROUP_MEMBERS = 32
#: The kinds a stored rationale line may name, spelled once. `label` and `semantic` are absent because
#: this module ports neither signal (module docstring), and a rationale line naming a kind outside this
#: tuple is a corrupted or foreign row, which `parse_rationale` refuses rather than renders.
RATIONALE_KINDS = ('temporal', 'topological')

#: An escalation rung's own rule id, as `platform/escalation.py` composes it (`chain.rule_id + '.stage' +
#: str(stage)`, stage numbering starting at 1 because stage 0 is the base incident's own delivery). Rungs
#: are exempt from grouping — see `is_escalation_rung`.
RUNG_RULE = re.compile(r'\.stage[1-9][0-9]*$')


class CorrelationError(ValueError):
    """A caller asked for a grouping outside the bounds this rule is defined within."""


@dataclass(frozen=True)
class Rationale:
    """One matched signal: its kind, the bounded sentence naming it, its 0..1 score, its references.

    `references` holds identifiers and numbers only — never a value copied out of an event. It exists
    because §4 wants the *why* to survive telemetry expiry: a digest of the declaration the path was read
    from stays true after the index that answered is rebuilt, where a quoted path would be unverifiable.
    """
    kind: str
    detail: str
    score: float
    references: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """The stored form of this signal: the sentence, its score, and its references nested under one key.

        Nested and not flattened, because the two halves change for different reasons: the sentence is
        wording this module owns, the references are identities read out of the declared plane. A reader
        that wants the path (`rca`, re-pointing a member) takes `references`; a view that wants one line
        takes `detail`, and cannot mistake a reference for prose.
        """
        return {'kind': self.kind, 'detail': self.detail, 'score': self.score,
                'references': dict(self.references)}


def _bound(name: str, value: Any, low: int, high: int) -> int:
    """One integer inside its declared range, refused otherwise (a configuration error, never a clamp)."""
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise CorrelationError(f'{name} must be {low}..{high}')
    return value


def _resource(event: Any) -> str | None:
    """The event's declared resource UUID, or None. Never derived from a name: §4.2 admits null."""
    value = event.get('resource_id') if isinstance(event, dict) else None
    return value if isinstance(value, str) and value else None


def _instant(event: Any) -> dt.datetime | None:
    """The event's own observed instant, or None when it does not carry a readable one.

    None here means *no proximity is claimed*, never a guessed one: `kv`'s signal fell back to the wall
    clock for an unparseable timestamp and said so in a comment; here an unreadable instant groups
    nothing, because a fallback clock would put an unrelated old condition inside a live window.
    """
    value = event.get('observed_at') if isinstance(event, dict) else None
    try:
        return timestamp(value)
    except (InvalidInventory, TypeError, ValueError):
        return None


def temporal(a: Any, b: Any, *, window_seconds: int = WINDOW_SECONDS) -> Rationale | None:
    """Co-occurrence of two conditions inside `window_seconds`, scored by how much of the window is left.

    Uses each event's own `observed_at`, never the arrival order of the rows: two verdicts about the same
    minute arrive in whichever order a producer sent them. A negative or absent gap is not possible here
    (`abs` of the difference), and an unparseable instant on either side answers None.

    This is the necessary half of the grouping rule and never a sufficient one. Call it directly only in
    a test that exists to show the half is not enough; product code composes through `link()`.

    Raises:
        CorrelationError: `window_seconds` is outside 1..`MAX_WINDOW_SECONDS`.
    """
    window = _bound('window_seconds', window_seconds, 1, MAX_WINDOW_SECONDS)
    first, second = _instant(a), _instant(b)
    if first is None or second is None:
        return None
    gap = abs((first - second).total_seconds())
    if gap > window:
        return None
    return Rationale(kind='temporal', detail=f'{gap:.0f} s apart (window {window} s)',
                     score=round(1.0 - gap / window, 4), references={'window_seconds': window})


def topological(a: Any, b: Any, graph: Any, *, max_hops: int = MAX_HOPS) -> Rationale | None:
    """A declared dependency path between the two events' resources, in either direction.

    `graph` is a `local_observe.topology.Topology` (duck-typed: anything answering `shortest_path` the
    same way). Only `found` and `absent` are read, and they are read differently: `found` names a path
    that exists, which is the whole claim this signal makes, while `absent` is a complete negative and
    lets the other direction still be tried. `incomplete` and `depth_exceeded` mean the search could not
    answer, and "could not answer" is never allowed to become "these two are related" — the same rule by
    which `platform/suppression.py` suppresses nothing on a truncated walk.

    Two events naming the *same* resource answer None: see the module docstring for what grouping on
    identity would do to a source-coverage condition. An undeclared or absent resource answers None for
    the same reason it groups nothing in v0.1: a signal never fabricates an id.

    Raises:
        CorrelationError: `max_hops` is outside 1..`MAX_SEARCH_HOPS`.
    """
    hops_limit = _bound('max_hops', max_hops, 1, MAX_SEARCH_HOPS)
    if graph is None:
        return None
    first, second = _resource(a), _resource(b)
    if first is None or second is None or first == second:
        return None
    reached: dict[str, Any] | None = None
    for source, target in ((first, second), (second, first)):
        try:
            answer = graph.shortest_path(source, target, hops_limit)
        except (OSError, sqlite3.Error, InvalidInventory, TypeError, ValueError):
            return None                  # an unreadable graph claims nothing in either direction
        if not isinstance(answer, dict):
            return None
        status = answer.get('status')
        if status == 'found':
            reached = answer
            break
        if status != 'absent':
            return None                  # incomplete / depth_exceeded / an answer shape unknown here
    if reached is None:
        return None                      # both directions answered "no path", which is an answer
    path = [node for node in reached.get('path') or [] if isinstance(node, str)]
    edges = [edge for edge in reached.get('edges') or [] if hasattr(edge, 'relation')]
    if len(path) < 2 or len(edges) != len(path) - 1:
        return None                      # `found` without a traversable path is not this shape
    hops = len(path) - 1
    if hops > hops_limit:
        return None
    relations = [str(edge.relation) for edge in edges]
    digest = next((str(edge.declaration_sha256) for edge in edges if getattr(edge, 'declaration_sha256', '')),
                  str((reached.get('revision') or {}).get('declaration_sha256') or ''))
    return Rationale(kind='topological',
                     detail=f"declared {' -> '.join(relations)} path, {hops} hop{'s' if hops != 1 else ''}"
                            f' ({reached.get("from")} depends on {reached.get("to")})',
                     score=round(1.0 / (1 + hops), 4),
                     references={'hops': hops, 'path': path, 'relations': relations,
                                 'direction': 'depends-on', 'declaration_sha256': digest})


def link(a: Any, b: Any, graph: Any, *, window_seconds: int = WINDOW_SECONDS,
         max_hops: int = MAX_HOPS) -> list[Rationale] | None:
    """The whole grouping rule for one pair of conditions: temporal AND a structural signal, or None.

    The composition is the invariant, and it is three lines: no temporal match, no link; a temporal match
    with nothing corroborating it, no link. `topological` is the only structural signal this build has
    (module docstring), so the tuple below has room for the second one a later card may port.

    Returns None — and therefore files a separate incident — when the composed rationale would not fit
    `MAX_RATIONALE_CHARS`. That direction is chosen deliberately: raising here would roll back the event
    that `Store.intake` had already validated and filed, so an over-wide rationale costs a second page
    rather than a lost finding.
    """
    time_match = temporal(a, b, window_seconds=window_seconds)
    if time_match is None:
        return None
    corroborating = [signal for signal in (topological(a, b, graph, max_hops=max_hops),)
                     if signal is not None]
    if not corroborating:
        return None
    signals: list[Rationale] = [time_match, *corroborating]
    try:
        document = rationale_document(signals)
    except CorrelationError:
        return None
    if len(document) > MAX_RATIONALE_CHARS:
        return None
    return signals


@dataclass(frozen=True)
class Grouping:
    """The bounds one installation groups under, validated once where they are wired.

    Validation at construction is the point: a bound outside its range is a configuration mistake, and a
    mistake discovered at the first admitted event would be discovered *inside* the transaction that had
    already filed that event — where the only honest answer left is to roll the finding back. Refusing
    here means a service that cannot start, which is louder than a service that drops events.

    `max_members` is carried for the writer, which enforces it where the group is actually counted
    (`state.Store.grouping_admission`); it is part of the same one place so a bound cannot be half-set.
    """
    window_seconds: int = WINDOW_SECONDS
    max_hops: int = MAX_HOPS
    promotion_threshold: int = PROMOTION_THRESHOLD
    max_members: int = MAX_GROUP_MEMBERS

    def __post_init__(self) -> None:
        """Refuse every bound outside its range, naming the one that moved."""
        _bound('window_seconds', self.window_seconds, 1, MAX_WINDOW_SECONDS)
        _bound('max_hops', self.max_hops, 1, MAX_SEARCH_HOPS)
        _bound('promotion_threshold', self.promotion_threshold, 1, MAX_PROMOTION_THRESHOLD)
        _bound('max_members', self.max_members, 1, MAX_GROUP_MEMBERS)

    def link(self, a: Any, b: Any, graph: Any) -> list[Rationale] | None:
        """`link()` under these bounds; the composition and its refusals are that function's."""
        return link(a, b, graph, window_seconds=self.window_seconds, max_hops=self.max_hops)


def rationale_document(signals: list[Rationale]) -> str:
    """The one stored form of a link: a canonical JSON array of the matched signals, in match order.

    Canonical so the same link composed twice is the same bytes, which is what lets a rationale be
    digested, compared across a restart, and re-read by a later card without a parser guessing.

    Raises:
        CorrelationError: A signal's references collide with the reserved names.
    """
    return canonical([signal.as_dict() for signal in signals])


def parse_rationale(stored: Any) -> list[dict[str, Any]]:
    """The stored lines of one rationale, or nothing at all when the row cannot be read.

    Read-side discipline for a table this module does not own the contents of after it commits: JSON that
    is not a list, an element that is not an object, a kind outside `RATIONALE_KINDS`, a score outside
    0..1, or a detail that is not a bounded string all answer `[]` — an unreadable explanation must not
    render as an explanation, exactly as `presentation.cause_info` refuses an unreadable record.

    A rationale holding more lines than a group may ever hold (`MAX_GROUP_MEMBERS`) is refused too rather
    than truncated: this platform never opens a group that wide, so the excess is corruption or a foreign
    writer, and a view that showed a partial explanation would be showing a claim nobody made.
    """
    if not isinstance(stored, str) or not 1 <= len(stored) <= MAX_RATIONALE_CHARS:
        return []
    try:
        rows = json.loads(stored)
    except ValueError:
        return []
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_GROUP_MEMBERS:
        return []
    lines: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            return []
        if row.get('kind') not in RATIONALE_KINDS or not isinstance(row.get('detail'), str):
            return []
        if not 1 <= len(row['detail']) <= 256:
            return []
        score = row.get('score')
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0.0 <= score <= 1.0:
            return []
        lines.append({'kind': row['kind'], 'detail': ' '.join(row['detail'].split()), 'score': float(score)})
    return lines


def is_escalation_rung(rule_id: Any) -> bool:
    """Whether this condition is one rung of an escalation ladder, and so exempt from grouping.

    A rung is filed under `<base rule>.stage<N>` and the ladder's own cursor tracks **one rung per
    incident** (`platform/escalation.py`, `Chain.stage_for`, whose states are keyed by incident id). Let a
    stage-2 event join the incident that opened it and the ladder has two conditions living on one
    incident while its cursor still counts one: the next rung it enqueues is the one the cursor already
    believes it filed, and the escalation either stalls or repeats a stage — the worst possible failure for
    a pager, so rungs are kept out of groups on both sides, as a member and as an anchor.

    The exemption is not a judgement that a rung is unrelated. It is the acknowledgement that a rung *is*
    the same cause, deliberately filed as its own condition so its delivery is a separate budgeted event.
    """
    return isinstance(rule_id, str) and bool(RUNG_RULE.search(rule_id))


def promote(severities: Any, distinct_resources: int, *,
            promotion_threshold: int = PROMOTION_THRESHOLD) -> str:
    """The group's severity: the loudest member, one rank toward critical when the impact is wide.

    `severities` are the member events' own admitted words (`vocabulary.ADMITTED_SEVERITIES`, which is
    quietest-first: `info`, `warning`, `critical`). The promotion is therefore index **+1** capped at the
    last rank; v0.1's ladder ran loudest-first and its `idx -= 1` is inverted here, and a port that
    copied that line would quietly make every wide incident quieter than its loudest member.

    There is no severity column on `incidents` — §5's schema has none and this card adds none — so this is
    a *derivation over the members' stored events*, recomputed on every read, which is also why it cannot
    drift when a member joins or resolves.

    Raises:
        CorrelationError: No severity was given, one is outside the admitted three, or the threshold is
            outside 1..`MAX_PROMOTION_THRESHOLD`. An unknown word is refused rather than read as `info`,
            because a group's loudness is the one number an operator acts on.
    """
    threshold = _bound('promotion_threshold', promotion_threshold, 1, MAX_PROMOTION_THRESHOLD)
    ladder = list(ADMITTED_SEVERITIES)
    if not isinstance(severities, (list, tuple)) or not severities:
        raise CorrelationError('A group has no member severities')
    try:
        ranks = [ladder.index(word) for word in severities]
    except ValueError:
        raise CorrelationError('A member severity is outside the admitted three') from None
    loudest = max(ranks)
    if not isinstance(distinct_resources, int) or isinstance(distinct_resources, bool):
        raise CorrelationError('Distinct resource count must be an integer')
    if distinct_resources >= threshold and loudest < len(ladder) - 1:
        loudest += 1
    return ladder[loudest]


def group_severity(members: Any, *, promotion_threshold: int = PROMOTION_THRESHOLD) -> str:
    """`promote` over member rows shaped as `{'severity': str, 'resource_id': str | None}`.

    A null resource contributes its severity and no resource: `state.validate_event` admits an unresolved
    event, and an incident whose cause is not linked yet is still one more *symptom*, not one less. The
    distinct-resource count that drives the promotion therefore counts declared identities only.
    """
    if not isinstance(members, (list, tuple)) or not members:
        raise CorrelationError('A group has no members')
    severities = [str(member.get('severity') or '') for member in members if isinstance(member, dict)]
    resources = {member.get('resource_id') for member in members
                 if isinstance(member, dict) and member.get('resource_id')}
    return promote(severities, len(resources), promotion_threshold=promotion_threshold)

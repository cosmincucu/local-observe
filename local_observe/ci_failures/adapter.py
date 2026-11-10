"""The platform boundary: canonical events out, the platform's own receipt back, no claims in between.

Why this file exists instead of `pipeline.py` writing to SQLite directly: `platform/state.py` owns
incident state, and `platform/intake.py` owns the rule/kind/severity decisions that make an event
admissible. This package's job ends at producing the events those layers admit and reporting what they
answered. Three statuses, and only three:

* `admitted` -- the platform took the event and named a record. This is the only status that may be
  described as "the platform has it".
* `not_configured` -- this process had no way to reach the platform (no URL, no credential, no
  admitted actor). The events are returned unsent and the pipeline says so in every report it emits.
* `refused` -- the platform was reached and said no, with its reason carried through verbatim.

There is no fourth status like `assumed`, and no code path here that treats writing a local JSON file
as admission: a file this process wrote is evidence about this process, and nothing else. The
`admission_ready` helper is the strongest claim available offline -- `state.validate_event` accepts the
shape -- and it says "admissible", never "admitted". That distinction is why the receipts, not a
counter, are what the CLI prints, and why every durable marker this source keeps is claimed from a
receipt: `claim_transitions` and `claimed_coverage_moves` answer "what did the platform take", and a
verdict it never took stays re-derivable instead of being remembered as sent.

The vocabulary is deliberately narrow and its cost is stated: `state.validate_event` admits exactly six
`kind` values (`availability`, `coverage`, `threshold`, `drift`, `anomaly`, `security`) and
`platform/vocabulary.py` carries no rows for a CI source. So a failed build is filed as
`availability` (the repository cannot produce a green build -- the same reading `platform/deadman.py`
uses for a job that stopped running) and a gap in this pipeline's own knowledge is `coverage`, never a
fabricated verdict. Adding a `ci` kind, or `gitea_ci` rows to the crosswalk, is a change to those two
modules and their own tests -- named as fan-out, not made here.

**How wide an incident is, and what closes it, lives here** (`plan_incident_keys`), because both are
claims about the platform's own identity rules and nowhere else can check them:

* *Width*: one incident per `(repository, workflow file, plane)` per rule, carried as the event's
  `resource_id`. `Store.intake` computes its condition key as
  `digest([source, rule_id, rule_version, resource_id, condition])`, so the resource is the only field
  this source may vary to set the width -- and `validate_event` admits a `resource_id` that is null or a
  canonical UUID, so the key travels as `uuid5(namespace, key)` (`resource_id_for_key`).
* *Loudness*: a main-plane failure is `critical`, any other plane that pages is `warning`, and the pull
  plane does not page at all: it is filed under `PULL_STATUS`, the one word `Store.intake` reads as
  "record it, open nothing". Severity cannot do this job -- `critical`, `warning` and `info` all open an
  incident when the status says `firing`.
* *Closure*: a green run newer than the key's last firing sends one `resolved` event under the same rule
  id, which is the half that keeps an incident from being a permanent scar. `Store.intake` accepts a
  `resolved` for a condition it has never seen (`incident_id` stays null, no transition, no outbox row),
  so closing a key nobody opened is a no-op and is reported as one.

**Coverage conditions open and close too.** A gap in what this poller could read is a `coverage` event,
and `platform/detections.py`, `platform/configdrift.py` and `platform/deadman.py` all spell that kind as
open-and-close ("could not be read (`firing`) or can be read again (`resolved`)"), so this source does the
same: at most one event per gap reason per poll. A gap this poll carries and the marker does not already
say is open fires; a gap a later poll gets without carrying resolves; a gap that is still open and
already admitted says nothing further until it closes -- the note on every run it lands on keeps arriving,
which is what makes a coarse card and what a card quotes, so a persistent gap stays visible without
re-paging. The two
questions are deliberately answered from two different sets. *Is the gap still there* is asked of every
note of every fact this poll read (`read_facts`), uncapped, because a reason this poll has in hand cannot
be reported as recovered -- a poll that read four gaps and filed three has not read the fourth away, and a
row it refused to parse is carried as "read, unknown" (`facts.RunFact.read_complete`) rather than as a read
that came back clean. *Is
this gap worth a page* is asked of the judged facts only, and capped by `MAX_COVERAGE_EVENTS`, because
that ceiling is what stops a thirty-job run declaring thirty incidents. And "the marker says open" is read
as "the marker says open **or** a firing for it is still owed": a gap that healed during a platform
outage is closed by the poll that reads it back, not opened one poll late by a replay.

**What licenses a closure.** A `resolved` for a gap is a claim about this poller's own reads, so it
travels on a read that came back: a run parsed whole, or -- the case a repository that stops building
leaves -- a poll whose own read of the forge completed, refused nothing and is passed in as
`poll_read`. A poll whose page walk failed, spent its page budget or left a row unparsed closes nothing,
and the run-less half is a claim about *witnesses* (no run this source reads any more carries the gap) and
not about the endpoint answering, which is why the poller's own wiring (`PollRead.coverage`: a gap that
needs no run to be true, like a log reader that is not wired) is carried on every poll and never closed by
an empty tick.

A coverage condition is the *poller's* subject, not a workflow's, so it is coalesced per reason
across the whole poll -- the platform keys a condition on `(source, rule_id, rule_version, resource_id,
condition)` and every coverage event names the same null resource and its own rule as its condition, so
two runs carrying one gap at one instant would be two verdicts at one watermark, which `Store.intake`
refuses outright.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import re
import uuid
from typing import Any
from collections.abc import Callable, Iterable, Mapping, Sequence
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.log import get_logger
from local_observe.platform.detections import event as canonical_event
from local_observe.platform.state import StateError, validate_event
from .facts import CardIdentity, CoverageNote, RunFact, incident_key
from .transports import CiFailureError

log = get_logger(__name__)

__all__ = ['AdmissionReceipt', 'IncidentKeyPlan', 'KeyTransition', 'PlatformAdmission', 'PollRead',
           'admission_ready', 'build_events', 'claim_transitions', 'claimed_coverage_moves',
           'plan_incident_keys', 'batch_snapshot', 'resource_id_for_key', 'coverage_rule',
           'COVERAGE_SUBJECT', 'SOURCE', 'RULE_FAILURE', 'RULE_STUCK', 'RULE_COVERAGE',
           'TERMINAL_EVIDENCE', 'COVERAGE_EVIDENCE', 'MAX_RUN_IDS_PER_EVENT']

#: The source name every event here carries. `state.label`'s character class applies, so `/`, space
#: and the repository's own name are excluded by construction, not by scrubbing.
SOURCE = 'gitea_ci'
RULE_FAILURE = 'ci.run.failed'
RULE_STUCK = 'ci.run.stuck'
RULE_COVERAGE = 'ci.intake.coverage'
#: The reserved *subject* this source files its gap markers under. It is not an incident key of any
#: workflow -- no run attributes to it -- and it exists so that "is this gap still open?" has one answer
#: per gap reason, the way an incident key has one answer per workflow. `Store.record_incident_keys` sees
#: a string shaped like a key and cannot tell the difference, which is the point: the store keeps
#: `{subject: {rule id: run ids}}` and this source decides what a subject means.
COVERAGE_SUBJECT = RULE_COVERAGE

#: How many coverage events one fact may *file*. It is a filing ceiling, and it is the reason a log gap on
#: a thirty-job run cannot become thirty incidents. Evidence references per event are fixed at one
#: here (`detections.event` builds the single reference), inside `state.validate_event`'s 1..20. It is not
#: a knowledge ceiling: `plan_incident_keys` reads a fact's whole `coverage` list to decide whether a gap
#: is still open, so a fourth note cannot close what the third note re-filed.
MAX_COVERAGE_EVENTS = 3
MIN_WINDOW_SECONDS = 60

TERMINAL_EVIDENCE = 'observed-snapshot'
COVERAGE_EVIDENCE = 'source-heartbeat'

#: The word the platform records an event under when the producer is reporting a verdict it must not
#: page on. `state.validate_event` admits `firing`/`resolved`/`unknown`, and `Store.intake` opens an
#: incident for a `firing` event and *nothing* for `unknown` -- it writes the condition row and stops
#: (`intake()`'s `if event['status'] == 'firing' and not incident_id:` branch is the only place an
#: incident is opened). So a pull-request build is recorded under this word and is not an incident; the
#: severity vocabulary offers no such rung (`critical`, `warning` and `info` all page, because severity
#: never gates the open), and inventing one would mean editing the intake rules this package may not.
PULL_STATUS = 'unknown'

#: How many run ids one coalesced event may name inside its evidence reference.
#: `state.validate_event` bounds an evidence parameter value to 256 characters, so the batch is shown
#: up to this many ids and the rest is counted, never dropped silently (`-cutN` in the snapshot id, and
#: `IncidentKeyPlan.superseded` for the runs a resolution swallowed).
MAX_RUN_IDS_PER_EVENT = 12
MAX_SNAPSHOT_CHARS = 200

#: The deterministic namespace the incident key is turned into a `resource_id` under. `*.invalid` is
#: the reserved never-resolvable domain, so this names a derivation and points at nothing: no host is
#: contacted, and no deployment's own identifier is embedded in an identity every install must share.
WORKFLOW_RESOURCE_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, 'ci-failures.local-observe.invalid')

#: The completed conclusion that closes a key: a green run. `skipped` and `neutral` are deliberately
#: absent -- a run that did not run is not evidence that whatever failed has been fixed, so it neither
#: fires nor resolves.
GREEN_CONCLUSION = 'success'

_KEY_SAFE = re.compile(r'[^a-zA-Z0-9_.:-]')

Admitter = Callable[[dict[str, Any]], Any]


@dataclass(frozen=True)
class AdmissionReceipt:
    """One event, and what the platform said about it.

    `event_status` is the status the *event* carried (`firing`, `resolved`, or `unknown` for a verdict
    this pipeline records but does not page on), and it travels on the receipt because the three are
    different claims: `admitted` says the platform stored the event, and only a `firing` event says the
    platform may now hold an incident for it. Without the word beside it, a report of "4 events
    admitted" would read like 4 incidents when two of them were a pull-request build and a closure.
    """
    record_id: str
    rule_id: str
    status: str
    reason: str = 'none'
    event_status: str = 'firing'

    @property
    def admitted(self) -> bool:
        return self.status == 'admitted'

    def as_dict(self) -> dict[str, Any]:
        return {'record_id': self.record_id, 'rule_id': self.rule_id, 'status': self.status,
                'reason': self.reason, 'event_status': self.event_status}


def _window_edges(fact: RunFact, now: dt.datetime) -> tuple[dt.datetime, dt.datetime]:
    """The evaluation slice one fact speaks for: observed .. judged, never longer than the ceiling.

    `state.validate_event` refuses a window whose start is not strictly before its end, one ending more
    than a minute in the future, and one spanning more than seven days. A run whose timestamps are
    missing -- or whose stored `updated_at` is somehow ahead of `now` -- therefore gets the shortest
    honest slice ending now, rather than a window that intake would reject or that silently claims hours
    this pipeline did not observe.

    It hands back the two instants rather than the text a canonical event wants, because a coalesced
    verdict folds several runs' slices into one span and folding text would be a string comparison
    pretending to be chronology. `_verdict_event` and `_coverage_event` do that fold and spell it with
    `utc_text`.
    """
    observed = fact.observed_at
    if observed is None or observed >= now:
        start = now - dt.timedelta(seconds=MIN_WINDOW_SECONDS)
    else:
        start = observed
    if now - start > dt.timedelta(days=6):
        start = now - dt.timedelta(days=6)
    if start >= now:
        start = now - dt.timedelta(seconds=MIN_WINDOW_SECONDS)
    return start, now


def resource_id_for_key(key: str) -> str:
    """The event's `resource_id` for an incident key: a derived UUID, never a declared resource.

    `state.validate_event` admits a `resource_id` that is null or a canonical UUID and refuses anything
    else, so the key cannot travel as its own readable text. It travels as `uuid5(namespace, key)`,
    which is stable forever and reversible in only one direction. Nothing here claims the UUID is
    declared in the inventory: like every other producer that files `observed-snapshot` events
    (`platform/pathcheck.py`, `platform/configdrift.py`), this source names a *subject*, and a subject
    that no topology declares simply groups with nothing (`correlation._bound_resource` finds no
    neighbour for it), which is the quiet direction, not the wrong one.
    """
    if not isinstance(key, str) or not key or len(key) > 128:
        raise CiFailureError('An incident key must be a bounded non-empty string')
    if _KEY_SAFE.search(key):
        raise CiFailureError('An incident key must stay inside the platform label character class')
    return str(uuid.uuid5(WORKFLOW_RESOURCE_NAMESPACE, key))


def batch_snapshot(key: str, run_ids: Iterable[int], *,
                   cap: int = MAX_RUN_IDS_PER_EVENT) -> str:
    """One bounded evidence id naming a whole batch: the key, the count, the first ids, the cut count.

    A coalesced verdict speaks for several runs and `state.validate_event` gives it nowhere to say so:
    a canonical event has no message field, and an evidence reference carries at most ten parameters
    whose keys are an approved list. So the batch goes in the one approved string the reference already
    uses (`snapshot_id`), and it degrades by *counting* what it drops -- `...-n40-r1-r2-cut38` says
    forty runs were folded, names two of them, and never pretends the two were all of them.
    """
    if not isinstance(key, str) or not key or len(key) > 128 or _KEY_SAFE.search(key):
        raise CiFailureError('A batch snapshot needs the incident key it belongs to')
    ids = sorted({int(run_id) for run_id in run_ids})
    if not ids:
        raise CiFailureError('A batch snapshot must name at least one run')

    def built(shown: Sequence[int]) -> str:
        cut = len(ids) - len(shown)
        text = f'cikey-{key}-n{len(ids)}' + ''.join(f'-r{run_id}' for run_id in shown)
        return text + (f'-cut{cut}' if cut else '')

    shown = ids[:max(0, int(cap))]
    while len(built(shown)) > MAX_SNAPSHOT_CHARS and shown:
        shown.pop()
    return built(shown)


def _plane_loudness(plane: str, rule_id: str) -> str:
    """How loud one verdict is, from the plane and the rule and nothing else.

    * a failure of the main plane is `critical` -- the repository cannot produce a green build;
    * a failure of any other plane that pages (a schedule, a branch build) is a `warning`;
    * a starvation is a `warning` whatever the plane: it is a runner that has not started, not a build
      that has gone wrong, and raising it to critical on main would be a loudness change nobody asked
      for;
    * the pull plane is `info`, because it is filed under `PULL_STATUS`, which opens nothing -- and
      recording a pull-request build must not put a `warning` in anybody's queue.

    `state.validate_event` admits exactly these three words and `vocabulary.py` carries no CI rows, so
    no fourth rung is available without editing the platform's rules, which this package may not do.
    """
    if plane == 'pull':
        return 'info'
    if rule_id == RULE_STUCK:
        return 'warning'
    return 'critical' if plane == 'main' else 'warning'


def _verdict_event(key: str, facts: Sequence[RunFact], rule_id: str, status: str, *, now: dt.datetime,
                   severity: str, source: str) -> dict[str, Any]:
    """One verdict about one incident key: the batch's window, its own resource, its run ids as evidence.

    The window is the union of what the runs were observed at (`_window_edges`' own rule, applied per run
    and then folded): the batch claims the span it actually read and no more, and `state.validate_event`
    still refuses a window that ends in the future or spans over seven days. `observed_at` is the newest
    instant in it, because that is the reading this verdict is speaking for.
    """
    edges = [_window_edges(fact, now) for fact in facts]
    start = min(first for first, _end in edges)
    end = max(last for _first, last in edges)
    if start >= end:
        start = end - dt.timedelta(seconds=MIN_WINDOW_SECONDS)
    parameters = {'snapshot_id': batch_snapshot(key, [fact.run_id for fact in facts])}
    return canonical_event(source, resource_id_for_key(key), rule_id, 'availability', status,
                           {'start': utc_text(start), 'end': utc_text(end)}, parameters,
                           query_type=TERMINAL_EVIDENCE, observed_at=utc_text(end), version='1',
                           severity=severity)


def coverage_rule(reason: str) -> str:
    """The rule id one gap reason is filed under -- the coverage condition's whole identity.

    A coverage event names no resource, and `detections.event` sets `condition` to the rule id, so this
    string *is* the condition the platform keys on. One gap, one condition, one incident: that is why the
    reason is coalesced across the poll rather than per run, and why the store's open marker for a gap is
    keyed by this id and not by an incident key.
    """
    return f'{RULE_COVERAGE}.{reason}'


def _coverage_event(rule_id: str, edges: Sequence[tuple[dt.datetime, dt.datetime]], status: str, *,
                    source: str) -> dict[str, Any]:
    """One coverage verdict: the span this poll read, the rule, and no resource of anybody's.

    The window is folded across every run that carried the gap (min start, max end), which is what keeps
    the single event honest about the span it claims, and is also what makes it *one* event: the platform
    refuses two verdicts for one condition at one watermark, and the per-run windows are what used to
    produce them.
    """
    start = min(first for first, _last in edges)
    end = max(last for _first, last in edges)
    if start >= end:
        start = end - dt.timedelta(seconds=MIN_WINDOW_SECONDS)
    return canonical_event(source, None, rule_id, 'coverage', status,
                           {'start': utc_text(start), 'end': utc_text(end)},
                           {'rule_id': RULE_COVERAGE}, query_type=COVERAGE_EVIDENCE,
                           observed_at=utc_text(end), version='1', severity='info')


@dataclass(frozen=True)
class KeyTransition:
    """What one incident key's state this poll moved, and the run id it moved on.

    `open_run` is the newest run this poll fired a verdict about, `closed_run` the newest run it
    resolved. A field left `None` keeps the stored value, so this is a patch, not a snapshot: two
    transitions for one key (a failure firing and a starvation closing) do not read each other.
    """
    key: str
    rule_id: str
    open_run: int | None = None
    closed_run: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {'key': self.key, 'rule_id': self.rule_id, 'open_run': self.open_run,
                'closed_run': self.closed_run}


@dataclass(frozen=True)
class EventClaim:
    """The one event in a plan that a marker move hangs on, and where the platform's answer is.

    A marker answers "did the platform take the verdict this source decided", so it may only be written
    from the receipt of the event that carried it -- and that needs the pair to exist before the send.
    `index` is the position of the event inside `IncidentKeyPlan.events`, which is the order
    `PlatformAdmission.admit` answers in, one receipt per event.
    """
    index: int
    key: str
    rule_id: str
    open_run: int | None = None
    closed_run: int | None = None

    def transition(self) -> KeyTransition:
        return KeyTransition(self.key, self.rule_id, self.open_run, self.closed_run)


@dataclass(frozen=True)
class IncidentKeyPlan:
    """The events one poll produces, and the state its own answers depend on.

    `superseded` names the failing runs that were *not* fired because this same poll saw a newer green
    run for their key. They are not lost -- they stay in this store's occurrence table and on the board,
    and their ids are counted here -- but they opened nothing, and a count of them belongs in the report
    rather than in a reader's inference from an absent event. The `resolved` event a resolution sends
    names only the green runs it speaks for; the runs it overtook are the report's claim, not the
    evidence's, because the closure is a verdict about the workflow being green and not an account of
    what it used to be.

    `spoken` is every `(key, rule_id)` this poll emitted an event about, and it is what lets the caller
    retire a stored-but-never-admitted verdict: a poll that has just said something about a condition has
    replaced whatever it said before.

    `carried` is the coverage rule ids this poll's own reads hold open -- the answer to "is this gap still
    here?" that the planner computed, handed back so the caller can tell a closure that is *obsolete* (the
    gap is being read again, so the stored word about it is a lie) from one that is merely *unspoken* (the
    marker is gone and this poll says nothing about the reason).
    """
    events: tuple[dict[str, Any], ...] = ()
    claims: tuple[EventClaim, ...] = ()
    superseded: tuple[int, ...] = ()
    recorded_rules: tuple[tuple[str, str], ...] = ()
    spoken: frozenset[tuple[str, str]] = frozenset()
    carried: frozenset[str] = frozenset()

    @property
    def transitions(self) -> tuple[KeyTransition, ...]:
        """The workflow-subject marker moves this poll decided, and the receipts now have to justify.

        A claim that moves neither half (`open_run` and `closed_run` both absent) is not a transition: it
        is the pull-plane verdict filed under `unknown`, which opened nothing and so owes no closure. It
        stays in `claims` because its receipt is still the platform's answer, and it stays out of here
        because a marker for a condition that never opened would have a later green run send a `resolved`
        nobody needs.
        """
        return tuple(claim.transition() for claim in self.claims
                     if claim.key != COVERAGE_SUBJECT
                     and (claim.open_run is not None or claim.closed_run is not None))

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(sorted({transition.key for transition in self.transitions}
                            | {key for key, _rule in self.recorded_rules}))

    @property
    def resolved_rules(self) -> frozenset[tuple[str, str]]:
        """`(key, rule_id)` pairs this poll closed -- what a `recovered[]` entry is matched against."""
        return frozenset((transition.key, transition.rule_id)
                         for transition in self.transitions if transition.closed_run is not None)


@dataclass(frozen=True)
class PollRead:
    """What one poll's own reading of the forge says, as distinct from what the runs it read say.

    `complete`: the page walk asked the forge and the answer came back -- no fetch failed, no page budget
    spent -- *and* every extra read the poll asked for (the bounded refresh of the runs it still calls
    in flight) answered too. This is the licence a poll that found no new run may close a gap on: with it,
    "the source has no current witness for that gap" is a statement this poll checked; without it, the poll
    does not know what it did not read, and says nothing.

    `coverage`: the gaps the poller knows about itself, with no run as their witness -- a log reader that
    was never wired is true on the tick that read a thousand green builds and on the tick that read
    nothing. They belong in the carried set of every poll, which is what keeps a configuration gap from
    being closed by an empty tick.
    """
    complete: bool = False
    coverage: tuple[CoverageNote, ...] = ()


def claim_transitions(plan: IncidentKeyPlan,
                      receipts: Sequence[AdmissionReceipt]) -> tuple[KeyTransition, ...]:
    """The marker moves the platform's answers justify writing, and only those.

    This is the whole difference between a marker that says "I decided this" and one that says "the
    platform has this". A verdict the platform never took -- no credential wired, a 503, a refusal --
    must leave the source free to say it again, so the marker stays unwritten and the event stays
    pending. Writing it at intent time is what made an incident losable: the fact behind it is behind the
    cursor by the next tick, and nothing would ever offer it again.

    A receipt list shorter than the plan is treated as "nothing was answered about those events", which
    is the direction that keeps the verdict re-derivable rather than claiming it landed.
    """
    claimed: list[KeyTransition] = []
    for claim in plan.claims:
        if claim.key == COVERAGE_SUBJECT or (claim.open_run is None and claim.closed_run is None):
            continue
        if claim.index < len(receipts) and receipts[claim.index].admitted:
            claimed.append(claim.transition())
    return tuple(claimed)


def claimed_coverage_moves(plan: IncidentKeyPlan,
                           receipts: Sequence[AdmissionReceipt]) -> tuple[KeyTransition, ...]:
    """The gap-marker moves the platform's answers justify, in the same receipt-driven shape.

    A coverage condition is closed by a later poll reading runs without the gap, so the marker may only
    move when the event that says so came back admitted; otherwise the next poll re-says it.
    """
    return tuple(claim.transition() for claim in plan.claims
                 if claim.key == COVERAGE_SUBJECT and claim.index < len(receipts)
                 and receipts[claim.index].admitted)


def plan_incident_keys(facts: Sequence[RunFact], states: Mapping[str, Mapping[str, Any]] | None = None,
                       *, now: dt.datetime, source: str = SOURCE,
                       pending: Mapping[str, Mapping[str, int]] | None = None,
                       read_facts: Sequence[RunFact] = (),
                       poll_read: PollRead | None = None) -> IncidentKeyPlan:
    """The whole event stream one poll produces: at most one event per incident key per rule.

    Three rules, in this order, and the second exists because of the first:

    1. **Width.** A verdict is about `(repository, workflow file, plane)`, carried as the event's
       `resource_id` (`incident_key` -> `resource_id_for_key`). `Store.intake` derives its condition key
       from `(source, rule_id, rule_version, resource_id, condition)`, so one key is one incident per
       rule and a tenth failing commit lands on the incident already open.
    2. **One event per key per rule per poll.** Two runs, one key, one `now` used to mean two events
       with the same `source_event_id` (`detections.event` derives it from rule, version, resource and
       window) and different contents, which `Store.intake` refuses as `Event retry changed contents`.
       Coalescing is what removes that refusal, so the batch is built *before* the event, never merged
       after it: the run ids are in the evidence, and the oldest and newest instant in the window.
    3. **The newest verdict is the only verdict.** A key whose newest run this poll is green is not
       fired and closed in the same breath -- `Store.intake` refuses two events for one condition at one
       watermark (`Conflicting evaluations at the same condition watermark`), and a page about a workflow
       that is green would be wrong twice over. So per key per rule a poll emits the firing, or the
       closure, or nothing.

    Args:
        facts: This poll's fresh facts. A fact that is neither failing, starved, nor completed-green
            (a run still in flight, say) contributes its coverage and nothing else.
        states: The store's current markers, `{incident key: {rule id: {'open': run, 'closed': run}}}`.
            Absent or empty means "nothing is known to be open", which is what the first tick gets -- and
            what a first tick with an old failure and a newer green run therefore files nothing about.
            The reserved subject `COVERAGE_SUBJECT` holds this source's open gap reasons, keyed by their
            rule id, and it is what lets a later poll say "read again" about a gap it can no longer see.
        now: The instant judging this poll. Every firing window ends here and never past it.
        read_facts: Every *other* fact this poll read -- the runs it parsed but judged nothing about (one
            still queued inside the stuck deadline, a skipped build, a run that arrived while the cursor
            was held back), and the carrier a refused row leaves behind (`facts.coverage_only_fact`, which
            is a fact-shaped note list with `unknown` everywhere a verdict would read). They can neither
            fire nor resolve a verdict, but their `coverage` is part of the answer to "is this gap still
            here", which is a question about this poller and not about any one build. A fact named in both
            lists is counted once. A carrier (`read_complete` False) must not be handed over in `facts` --
            that raises: as a verdict it would be read as a starvation under an identity nothing can match.
        pending: Verdicts this source decided that the platform never took, as
            `{incident key: {rule id: run id}}`. They hold the key open for the closure rule -- a newer
            green run retires an unsent firing as a resolution instead of re-offering it -- but they are
            not markers, and no receipt has said the platform holds them. Under the reserved
            `COVERAGE_SUBJECT` a non-zero run id is the run that carried the gap, so it also means "a
            firing for this gap is still owed", which is what keeps a gap that healed during an outage
            from being opened one poll late by its own replay.
        poll_read: What this poll's *own* reading says, as opposed to what the runs it read say: whether
            the walk came back whole, and which gaps the poller knows about itself. Absent (the default)
            means "the caller has said nothing about its own read", which licenses no closure on a poll that
            read no runs -- the safe direction for a caller that does not know how to answer.

    Raises:
        CiFailureError: A fact cannot be attributed at all (no run id), a caller hands over something
            that is not a fact, or a caller hands a *refused* row (`read_complete` False) to `facts`,
            where it would be read as a starved run under a fabricated identity.
    """
    markers = states or {}
    unacknowledged = pending or {}
    verdicts: dict[tuple[str, str], list[RunFact]] = {}
    greens: dict[str, list[RunFact]] = {}
    gap_spans: dict[str, list[tuple[dt.datetime, dt.datetime]]] = {}
    gap_carrier: dict[str, int] = {}
    carried: set[str] = set()
    read_spans: list[tuple[dt.datetime, dt.datetime]] = []
    newest_read = 0
    judged = set()
    incomplete_reads = 0
    for fact in facts:
        if not isinstance(fact, RunFact) or fact.run_id <= 0:
            raise CiFailureError('A fact must carry a run id to be attributable')
        if not fact.read_complete:
            # The carrier of a row this poll refused is a note list shaped like a fact. As a verdict it
            # reads as a starved run (`status != completed`) filed under a workflow identity no run can
            # ever match, so no green build could close it -- and it would fire on every poll that refused
            # the row. It belongs in `read_facts`, which is the list that holds gaps open, and nowhere else.
            raise CiFailureError('A refused row is coverage, not a verdict: pass it in read_facts')
        judged.add(fact.run_id)
        span = _window_edges(fact, now)
        read_spans.append(span)
        newest_read = max(newest_read, fact.run_id)
        # Uncapped, and of every run the poll read, green included: `job-logs-not-wired` is a fact about
        # this poller's wiring, and a poll that happened to read only passing builds has not read that gap
        # away. Nor has a poll that read four gaps and was allowed to file three -- the fourth note is in
        # this process's hands, and reporting the reason as recovered would be a claim about the platform
        # that this poll's own data contradicts. `MAX_COVERAGE_EVENTS` caps *filing*, not knowing.
        carried.update(coverage_rule(note.reason) for note in fact.coverage)
        if fact.status != 'completed' or fact.is_failure:
            # Filing is the stricter question: only a verdict that has gaps to declare files them. A green
            # run whose log was never read is not an incident waiting to happen -- nothing depends on what
            # a build that passed did not show, and filing coverage for it would open an incident on every
            # successful build.
            for note in fact.coverage[:MAX_COVERAGE_EVENTS]:
                rule_id = coverage_rule(note.reason)
                gap_spans.setdefault(rule_id, []).append(span)
                gap_carrier[rule_id] = max(gap_carrier.get(rule_id, 0), fact.run_id)
        key = incident_key(fact)
        if fact.status != 'completed':
            verdicts.setdefault((key, RULE_STUCK), []).append(fact)
        elif fact.is_failure:
            verdicts.setdefault((key, RULE_FAILURE), []).append(fact)
        elif fact.conclusion == GREEN_CONCLUSION:
            greens.setdefault(key, []).append(fact)
    for fact in read_facts:
        # Read, judged nothing: the runs this poll parsed and could not file a verdict about. Their
        # coverage is knowledge (see above) and their span is part of what this poll can claim to have
        # read, which is what a gap closure is measured against; they fire nothing and resolve nothing.
        if not isinstance(fact, RunFact) or fact.run_id <= 0:
            raise CiFailureError('A fact must carry a run id to be attributable')
        if fact.run_id in judged:
            continue
        judged.add(fact.run_id)
        if not fact.read_complete:
            # The notes of a row this poll could not parse are held as knowledge -- the reads behind the
            # refusal happened, and a gap this process met is not unread -- but the row is not a read that
            # came back whole: it licenses nothing and its run id is not evidence of a clean re-read, so it
            # joins neither the closure window nor the `closed_run` stamp.
            incomplete_reads += 1
            carried.update(coverage_rule(note.reason) for note in fact.coverage)
            continue
        read_spans.append(_window_edges(fact, now))
        newest_read = max(newest_read, fact.run_id)
        carried.update(coverage_rule(note.reason) for note in fact.coverage)
    # Gaps the poller sees in itself, whether or not it read a run this tick. `job-logs-not-wired` is the
    # one that has no run as its witness: the wiring is, so a poll that read nothing has not read it away.
    if poll_read is not None:
        carried.update(coverage_rule(note.reason) for note in poll_read.coverage)
    events: list[dict[str, Any]] = []
    claims: list[EventClaim] = []

    def speak(event: dict[str, Any], subject: str, rule_id: str, *, open_run: int | None = None,
              closed_run: int | None = None) -> None:
        """Record one thing this poll says, in the order `PlatformAdmission.admit` will answer it."""
        claims.append(EventClaim(len(events), subject, rule_id, open_run, closed_run))
        events.append(event)

    # One coverage event per gap reason per poll, in rule order, its window folded across every run that
    # carried the gap. The reason is the condition (`detections.event` sets `condition` to the rule id and
    # a coverage event names no resource), so two runs of one gap at one instant used to be two verdicts
    # at one watermark -- which is the answer `Store.intake` gives that, namely none.
    #
    # "Already said" is the union of the marker and the owed rows: a firing this source decided and the
    # platform never took is still a firing that stands, whether it is claimed (marker) or owed (pending,
    # whose stored event the caller replays byte for byte). Saying it again every poll would replace that
    # stable event with a fresh window each tick, which is both churn and the reason the pending table
    # exists. What keeps a persistent gap visible is the note on every run it lands on (`runs.detail`, the
    # coarse fingerprint and the card's own gap list), not a re-page.
    open_coverage = {rule_id for rule_id, rung in (markers.get(COVERAGE_SUBJECT) or {}).items()
                     if int(rung.get('open') or 0)}
    open_coverage |= {rule_id for rule_id, run in (unacknowledged.get(COVERAGE_SUBJECT) or {}).items()
                      if int(run or 0)}
    for rule_id in sorted(set(gap_spans) - open_coverage):
        speak(_coverage_event(rule_id, gap_spans[rule_id], 'firing', source=source),
              COVERAGE_SUBJECT, rule_id, open_run=gap_carrier[rule_id])
    # A gap that a poll no longer carries is a gap that closed, and the licence to say so is a read that
    # came back. Two things license it: a run this poll parsed whole, or -- for the tick a quiet repository
    # gets, which asks the forge and is answered with nothing new -- a poll whose own read completed and
    # left no row unparsed (`poll_read`, and `incomplete_reads` counted above). A poll whose walk failed,
    # spent its page budget or refused every row it reached has read nothing back and resolves no gap, and
    # so does a caller that passed no `poll_read` at all.
    closure_spans = read_spans
    if not closure_spans and poll_read is not None and poll_read.complete and not incomplete_reads:
        # The window a run-less closure cites is this poll's own slice, which is the shortest honest span
        # ending now: the claim is "no run this source reads any more carries this gap", and it is not the
        # claim that the endpoint answered -- on a quiet repository nothing asked it. A gap that is still
        # broken is re-filed by the next build that trips it, which is the cost of the alternative: an
        # incident that stays open forever on a branch nobody builds again.
        closure_spans = [(now - dt.timedelta(seconds=MIN_WINDOW_SECONDS), now)]
    if closure_spans:
        for rule_id in sorted(open_coverage - carried):
            speak(_coverage_event(rule_id, closure_spans, 'resolved', source=source),
                  COVERAGE_SUBJECT, rule_id, open_run=0, closed_run=newest_read or None)

    superseded: list[int] = []
    recorded: list[tuple[str, str]] = []
    considered: set[tuple[str, str]] = set(verdicts)
    for key in greens:
        considered.update((key, rule_id) for rule_id in (RULE_FAILURE, RULE_STUCK))
    for key, rule_id in sorted(considered):
        members = sorted(verdicts.get((key, rule_id), ()), key=lambda item: item.run_id)
        newest_bad = members[-1].run_id if members else 0
        fact_plane = members[-1].plane if members else ''
        fresh = sorted(greens.get(key, ()), key=lambda item: item.run_id)
        newest_green = fresh[-1].run_id if fresh else 0
        marker = dict((markers.get(key) or {}).get(rule_id) or {})
        opened = int(marker.get('open') or 0)
        closed = int(marker.get('closed') or 0)
        # A verdict the platform never took is one this source still stands by, so it holds the key open
        # for the closure rule: a newer green run then retires the unsent firing as a resolution instead
        # of leaving it waiting in the table to page somebody about a build that is green.
        opened = max(opened, int((unacknowledged.get(key) or {}).get(rule_id) or 0))
        if members and not (newest_green and newest_green >= newest_bad):
            pull = _all_pull(members)
            # A starvation keeps the one severity it has always had -- a runner that never started is a
            # warning on any plane, and raising it to critical on main would be a loudness change nobody
            # asked for. Only the failure verdict reads its loudness off the plane.
            speak(_verdict_event(key, members, rule_id,
                                 PULL_STATUS if pull else 'firing', now=now,
                                 severity=_plane_loudness(fact_plane, rule_id),
                                 source=source), key, rule_id,
                  open_run=None if pull else max(opened, newest_bad))
            if pull:
                recorded.append((key, rule_id))
            continue
        if members:
            superseded.extend(fact.run_id for fact in members)
        if not newest_green or not opened or newest_green < opened or newest_green <= closed:
            continue
        speak(_verdict_event(key, fresh, rule_id, 'resolved', now=now, severity='info',
                             source=source), key, rule_id, open_run=0, closed_run=newest_green)
    return IncidentKeyPlan(tuple(events), tuple(claims), tuple(sorted(set(superseded))),
                           tuple(sorted(set(recorded))),
                           frozenset((claim.key, claim.rule_id) for claim in claims),
                           frozenset(carried))


def _all_pull(members: Sequence[RunFact]) -> bool:
    """Whether every run this batch speaks for is a pull-request build.

    One batch is one key and the key carries the plane, so a group is single-plane in practice. The
    `all` is the safe half: a mixed group must never be filed as `unknown`, because that word is what
    keeps a main-plane failure from ever becoming an incident.
    """
    return bool(members) and all(fact.plane == 'pull' for fact in members)


def build_events(fact: RunFact, identity: CardIdentity, *, now: dt.datetime,
                 source: str = SOURCE) -> list[dict[str, Any]]:
    """The canonical events one fact describes: coverage first, then the verdict it makes judgeable.

    The order is `platform/detections.evaluate`'s, and it is not cosmetic -- an intake that opens an
    incident for a firing event must already have heard that the evidence behind it is thin.

    This is the single-fact view of `plan_incident_keys` with no markers (one key, so nothing can
    coalesce and nothing is known to be open, so no closure is claimed). A poller that has several runs
    of one workflow to report calls `plan_incident_keys` instead: one fact at a time through this
    function is exactly how two runs came to carry one event id, and the tests keep the two views
    agreeing on one fact.

    Raises:
        CiFailureError: The fact cannot be expressed at all (no run id), which means the caller has a
            bug rather than a gap: a missing field is a `CoverageNote`, never a dropped event.
    """
    if not isinstance(fact, RunFact) or fact.run_id <= 0:
        raise CiFailureError('A fact must carry a run id to be attributable')
    return list(plan_incident_keys([fact], None, now=now, source=source).events)



class PlatformAdmission:
    """Send canonical events through an injected admitter and keep the receipts it gives back.

    The admitter is a callable the *host* supplies -- in a real deployment, a function holding a
    producer `Actor` that calls `Store.put_evidence` for the referenced sample and then `Store.intake`
    for the event, exactly in that order (`platform/intake.py`'s rule: an event whose sample was never
    stored is a dead link). This package holds no `Actor`, no credential and no store handle, so it
    cannot do that itself, and it will not pretend otherwise: with no admitter, every event comes back
    `not_configured` and the report says so.
    """

    def __init__(self, admitter: Admitter | None = None, *, source: str = SOURCE) -> None:
        if admitter is not None and not callable(admitter):
            raise CiFailureError('A platform admitter must be callable or absent')
        self.admitter = admitter
        self.source = source

    @property
    def configured(self) -> bool:
        return self.admitter is not None

    def admit(self, events: Sequence[Mapping[str, Any]]) -> list[AdmissionReceipt]:
        """Hand each event over, in order, and return one receipt per event.

        An exception from the admitter is reported as `refused` with the exception class, not swallowed
        and not retried here: the caller's cursor has already advanced past the fact, and the honest
        report is "the platform did not take these", which is a coverage statement about the intake
        rather than a claim about the build.
        """
        receipts: list[AdmissionReceipt] = []
        for position, event in enumerate(events):
            record_id = str(event.get('source_event_id') or f'event-{position}')
            rule_id = str(event.get('rule_id') or 'unknown')
            # Carried through verbatim: `firing` may have opened something, `resolved` may have closed
            # something, `unknown` did neither, and `admitted` on its own says only which of the three
            # *could* have happened. A reader who has to guess from the rule id will guess wrong about a
            # `resolved` event under the same rule id as a `firing` one.
            verdict = str(event.get('status') or 'unknown')
            if self.admitter is None:
                receipts.append(AdmissionReceipt(record_id, rule_id, 'not_configured',
                                                 'no platform admitter is wired', verdict))
                continue
            try:
                answer = self.admitter(dict(event))
            except (StateError, CiFailureError, ValueError) as exc:
                receipts.append(AdmissionReceipt(record_id, rule_id, 'refused',
                                                 str(exc)[:200] or type(exc).__name__, verdict))
                continue
            except Exception as exc:  # a transport/OS failure is still an answer about the send
                log.warning('Platform admission raised', extra={'error_class': type(exc).__name__})
                receipts.append(AdmissionReceipt(record_id, rule_id, 'refused', type(exc).__name__,
                                                 verdict))
                continue
            status, reason = _classify(answer)
            record = answer.get('event_id') if isinstance(answer, Mapping) else None
            receipts.append(AdmissionReceipt(str(record or record_id), rule_id, status, reason, verdict))
        return receipts


def _classify(answer: Any) -> tuple[str, str]:
    """Turn whatever the host's admitter returned into `admitted` or `refused`, with a reason.

    The reason comes from `reason`, and failing that from the stable `error` code, and from nowhere else
    in a 2xx body: `platform/api.py` writes its refusal text into `detail`, which is a rendered exception
    message, and a receipt reason is stored in this source's own state file and printed in its report.
    `platform_client._error_code` enforces the same rule for a non-2xx body -- the stable code travels, the
    prose does not -- and this is the 2xx half of that rule: `reason` is what `platform_client._receipt`
    reads for a 2xx refusal, and `error` is the field name the platform's own API uses for a stable code,
    so a host admitter that answers either is heard. A body that names neither is refused as `rejected`.
    """
    if answer is None:
        return 'refused', 'the admitter returned nothing'
    if isinstance(answer, Mapping):
        if answer.get('accepted') is True or answer.get('event_id') or answer.get('incident_id'):
            return 'admitted', 'none'
        return 'refused', str(answer.get('reason') or answer.get('error') or 'rejected')[:200]
    if answer is True:
        return 'admitted', 'none'
    return 'refused', f'unrecognised admitter answer {type(answer).__name__}'


def admission_ready(events: Sequence[Mapping[str, Any]], *, now: dt.datetime) -> int:
    """Prove every event is *admissible* by running the platform's own validator over it.

    This is an offline proof about shape: `state.validate_event` is the same function `Store.intake`
    calls before it writes a row, so an event that passes here could not be refused for being
    malformed. It is not evidence that a send happened -- that is what `AdmissionReceipt` is for.

    Returns the number of events checked, so a caller can assert it checked the ones it meant to.
    """
    if not events:
        return 0
    for event in events:
        validate_event(dict(event), now)
    return len(events)

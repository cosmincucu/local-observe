"""The bounded poller: read, record, decide, deliver, check in -- in that order, one commit at a time.

One tick, in the order the code runs it:

1. **Reconcile first.** Before anything new is read, the outlet asks the board what already happened to
   the intents left pending by an earlier process. Reconciling before reading (rather than after
   delivering) is what makes a restart converge on the truth: an intent whose write landed is adopted,
   and an intent whose write never left is attempted, and neither answer depends on what this process
   remembers.
2. **Verify the read** with one bounded request (`ActionsSource.verify_access`). A credential that
   cannot read the repository fails here instead of half-way through a filing.
3. **Walk pages, and commit per page.** Facts and the cursor advance in one transaction per page, so a
   process killed between pages loses the work of at most the page in flight -- and re-reading that
   page is harmless, because `runs.event_key` and `occurrences(fingerprint, run_id)` are the dedup keys.
   A page whose fetch fails stops the walk, leaving the cursor at the last page that committed.
4. **Refuse per row, not per page.** A malformed run object is a durable `refusals` row naming the
   field, and the walk continues past it. Skipping silently would lose a failure; aborting the tick on
   one bad row would let a single poisoned run freeze ingestion forever.
5. **Decide, then deliver** (`outlet.plan` then `outlet.drain`), with the intent rows already on disk.
    **Check in last.** `Store.record_success` judges the gap against the *previous* check-in and writes
    the lapse row before moving the heartbeat, in the same transaction -- so a poller that returns after
    three hours of silence leaves a three-hour lapse behind it instead of erasing one. A tick that could
    not read its source does not check in at all: a pipeline that cannot read CI is not delivering
    anything, whatever state its process is in.

What a tick does *not* do is sweep its own heartbeat. `check_heartbeat` is read-only and is driven by a
different process (`--check-heartbeat`, its own scheduler entry): a monitor that runs inside the thing
it monitors cannot observe that the thing stopped.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import datetime as dt
from pathlib import Path
from typing import Any
from collections.abc import Mapping, Sequence

from local_observe.log import get_logger
from .adapter import (COVERAGE_SUBJECT, GREEN_CONCLUSION, AdmissionReceipt, EventClaim, IncidentKeyPlan,
                      KeyTransition, PULL_STATUS, PlatformAdmission, PollRead, RULE_STUCK,
                      claim_transitions, claimed_coverage_moves, plan_incident_keys)
from .facts import (CoverageNote, DEFAULT_MAIN_BRANCHES, RunFact, card_identity, coverage_only_fact,
                    incident_key, parse_run)
from .outlet import BoardOutlet, DrainReport, OutletConfig, ReconcileReport, Thresholds
from .store import FAILING_OUTCOMES, CiFailureStore
from .transports import (ActionsSource, BoardClient, CiFailureError, HttpJsonTransport, MalformedSource,
                         PaginationBudget, ScopeRefused, SourceUnavailable)

log = get_logger(__name__)

__all__ = ['Pipeline', 'PipelineConfig', 'Service', 'TickReport', 'build_service', 'environment_config',
           'COVERAGE_SOURCE', 'DEFAULT_HEARTBEAT_DEADLINE_SECONDS', 'DEFAULT_STUCK_AFTER_SECONDS']
#: The starved-runner class: a run queued or waiting, unstarted, for at least this long.
DEFAULT_STUCK_AFTER_SECONDS = 1200
#: How long the poller may be silent before an independent monitor calls it a lapse. Two and a half
#: times a default five-minute interval: one missed tick is a slow API, two misses is a process problem.
DEFAULT_HEARTBEAT_DEADLINE_SECONDS = 900

#: Non-terminal statuses worth watching for starvation. `in_progress` is excluded: a running job is
#: not waiting for a runner, and calling it stuck would page on load rather than on failure.
QUEUED_STATUSES = frozenset({'queued', 'waiting', 'blocked'})

COVERAGE_SOURCE = 'ci-failures-poller'


@dataclass(frozen=True)
class PipelineConfig:
    """Behaviour an operator tunes, plus the identity of what is being polled.

    `repository` is `owner/name` on the forge and nothing more: no host, no URL, no service name. The
    deployment names the host in its own configuration; the product only ever needs the path pair, and
    keeping that line is what lets this package ship without naming anybody's topology.
    """
    repository: str
    main_branches: tuple[str, ...] = DEFAULT_MAIN_BRANCHES
    stuck_after_seconds: int = DEFAULT_STUCK_AFTER_SECONDS
    heartbeat_deadline_seconds: int = DEFAULT_HEARTBEAT_DEADLINE_SECONDS
    max_pages: int = 20
    per_page: int = 50
    max_open_run_refresh: int = 20
    file_cards: bool = True
    thresholds: Thresholds = field(default_factory=Thresholds)
    run_link_base: str = ''
    seed_cursor: int | None = None

    def __post_init__(self) -> None:
        if not any(char == '/' for char in str(self.repository)):
            raise CiFailureError('Pipeline repository must be owner/name')
        if not 60 <= int(self.stuck_after_seconds) <= 86400:
            raise CiFailureError('Stuck deadline is out of range')
        if not 60 <= int(self.heartbeat_deadline_seconds) <= 86400:
            raise CiFailureError('Heartbeat deadline is out of range')
        if int(self.heartbeat_deadline_seconds) < int(self.stuck_after_seconds) // 2:
            raise CiFailureError('Heartbeat deadline is shorter than the work it bounds')
        if not 1 <= int(self.max_pages) <= 20 or not 1 <= int(self.per_page) <= 50:
            raise CiFailureError('Page bounds are out of range')
        if not 0 <= int(self.max_open_run_refresh) <= 50:
            raise CiFailureError('Open-run refresh bound is out of range')
        if not 1 <= len(tuple(self.main_branches)) <= 8:
            raise CiFailureError('Main-branch set must be small and non-empty')
        for branch in self.main_branches:
            if not isinstance(branch, str) or not 1 <= len(branch) <= 100 or '/' in branch:
                raise CiFailureError('Main branch names are unbounded')
        if self.seed_cursor is not None and (isinstance(self.seed_cursor, bool)
                                             or not isinstance(self.seed_cursor, int)
                                             or self.seed_cursor < 0):
            raise CiFailureError('Seed cursor must be a non-negative integer')


@dataclass(frozen=True)
class TickReport:
    """One tick's answer, in a shape a log line, a report or a test can read.

    `events` counts what the boundary was offered and `receipts` carries the platform's own word on each,
    so the incident claims stay separable from the send claims. Three of the fields exist because an
    event count alone cannot describe this poller's output any more:

    * `keys` is how many incident subjects the poll spoke about -- one per (repository, workflow, plane).
      Two runs of one workflow are one key, which is the coalescing rule made readable from outside. A
      coverage gap is not one of these subjects and is not counted here; it is its own condition, and its
      events show up in `events` and `resolved`.
    * `resolved` is how many of those events closed something as far as this poller knows -- a workflow
      verdict or a coverage gap that a later poll read back. They are not new incidents, and
      `platform_admission: admitted` on a tick that fixed nothing would otherwise look like a tick that
      opened two.
    * `superseded` names the failing runs the poll did *not* fire, because the same workflow had a newer
      green run in the same page walk. They are recorded, counted and (if a board is wired) filed; they
      just do not open an incident, and an empty-looking event count should say so.

    `recovered` names the runs this store had already reported as starved and that now arrived with a
    verdict which is not a failure. Each entry's `incident_statement` says what was actually handed to the
    platform about the incident that starvation opened: `sent: True` means a `resolved` event was offered
    for that key -- whether the platform closed anything is the receipt's answer, not this one. The four
    answers are `resolved-offered`, `recorded-not-opened`, `open-not-closed` (this source's own marker
    still says the key is open and this poll closed nothing, which is what a refused closure and an
    incident closed by hand both look like from here) and `nothing-known-open`.

    `recorded` is the count of new facts and `events` the count of canonical events this poll offered.
    One event per (repository, workflow, plane) per rule is the *verdict* half; the other half is one
    coverage event per gap reason this poll carried or closed. So `events` is not bounded by `recorded`
    and can be smaller or larger than it: a poll of three starved runs with three gaps each is nine
    coverage verdicts and three workflow verdicts over three new facts, and a poll that only re-offers a
    stored verdict can report events with nothing recorded at all. A tick that filed nine verdicts for
    nine runs of one workflow is the old shape this report no longer produces.

    `pending_verdicts` counts the verdicts this store decided that the platform never took -- kept in the
    `verdicts_pending` table and re-offered until something answers. It is the number that says "the
    incident you can see on the board is not everything that happened". It is also a number with a ceiling:
    the table keeps `store.PENDING_VERDICTS_BOUND` rows, so on a backlog bigger than that the count reads
    steady at the bound and the rows above it are in `abandoned` with the bound as their reason. Whoever
    wants "how many verdicts did this source decide" adds the two.

    `abandoned` names the owed verdicts this tick gave up on, and it is the counterparty of that claim: a
    row leaves the table only when re-offering it cannot work, and each route says which -- one of the two
    ceilings `store.expire_pending_verdicts` applies (offered too many times, or citing evidence older than
    the lifetime the event itself claims), the row-count bound above, or this poll's own judgement that a
    stored *coverage closure* has nothing true left to say (see `_admit`: the gap it closed is being read
    again). Every drop is listed here rather than disappearing from `pending_verdicts` alone.
    An entry is `{'key', 'rule_id', 'reason', 'attempts', 'decided_at', 'event_status', 'reoffered',
    'withdrawn'}`. Those last two are the second half of the sentence, and they are the planner's answer
    rather than the store's, read off the *status* this poll spoke about that same `(key, rule_id)`:

    * **Neither.** This poll said nothing about the pair -- a verdict about a run this store has already
      passed cannot be re-decided -- so the page really is gone and the exit code that row held at "the
      platform refused" frees.
    * **`reoffered`.** This poll files the *same condition* again as a `firing`, with a fresh window: a gap
      it is still reading, where the row it just deleted was the only thing telling the planner the
      condition had already been said. The page the retired row stood for is cancelled; the condition is not.
    * **`withdrawn`.** This poll spoke the *other direction* -- a `resolved`, or a pull-plane `unknown`,
      which opens nothing. The owed firing is not repeated and not merely dropped: a newer verdict replaced
      it, and calling that `reoffered` would report a page on the tick that cancelled one.

    `receipts` travels in the printed report next to the counts, because "the platform has these events"
    is a claim about an answer this process received: when it comes back `refused`, the operator has to
    be able to read which event and with what reason without a second run against a live store.
    """
    scanned: int = 0
    recorded: int = 0
    refusals: int = 0
    cursor: int = 0
    complete: bool = True
    reconciled: ReconcileReport | None = None
    planned: tuple[str, ...] = ()
    drained: DrainReport | None = None
    events: int = 0
    keys: int = 0
    resolved: int = 0
    superseded: tuple[int, ...] = ()
    receipts: tuple[AdmissionReceipt, ...] = ()
    recovered: tuple[dict[str, Any], ...] = ()
    pending_verdicts: int = 0
    abandoned: tuple[dict[str, Any], ...] = ()
    lapse: dict[str, Any] | None = None
    heartbeat: dict[str, Any] | None = None
    error: str | None = None

    @property
    def admitted(self) -> int:
        return sum(1 for receipt in self.receipts if receipt.admitted)

    @property
    def refused_receipts(self) -> int:
        """How many receipts came back an answer that was not admission.

        This is not the printed `refused` count, and the difference is the whole point of having both:
        printed `refused` is `events - admitted`, which counts an event nobody was wired to receive,
        because a ramp-up deployment that has not connected the platform really did have every event
        refused by the absence of a destination. This property counts only receipts carrying an answer --
        `refused`, not `not_configured` -- and it is what the CLI exits on, because "the platform said
        no" and "there is no platform" need different actions and one exit code would hide one behind
        the other.
        """
        return sum(1 for receipt in self.receipts
                   if not receipt.admitted and receipt.status != 'not_configured')

    @property
    def platform_admission(self) -> str:
        """How the platform boundary answered, as one word: never assumed, always read back."""
        if not self.receipts:
            return 'no-events'
        statuses = {receipt.status for receipt in self.receipts}
        if statuses == {'admitted'}:
            return 'admitted'
        if statuses == {'not_configured'}:
            return 'not-configured'
        return 'mixed' if 'admitted' in statuses else 'refused'

    def as_dict(self) -> dict[str, Any]:
        return {'scanned': self.scanned, 'recorded': self.recorded, 'refusals': self.refusals,
                'cursor': self.cursor, 'complete': self.complete,
                'planned': list(self.planned), 'events': self.events, 'keys': self.keys,
                'resolved': self.resolved, 'superseded': list(self.superseded),
                'platform_admission': self.platform_admission,
                'admitted': self.admitted, 'refused': self.events - self.admitted,
                'refused_answered': self.refused_receipts,
                'receipts': [receipt.as_dict() for receipt in self.receipts],
                'reconciled': None if self.reconciled is None else self.reconciled.as_dict(),
                'drained': None if self.drained is None else self.drained.as_dict(),
                'recovered': [dict(item) for item in self.recovered],
                'pending_verdicts': self.pending_verdicts,
                'abandoned': [dict(item) for item in self.abandoned],
                'abandoned_verdicts': len(self.abandoned),
                'lapse': self.lapse, 'heartbeat': self.heartbeat, 'error': self.error}


class Pipeline:
    """Wires the reader, the store and the outlet, and runs one tick at a time."""

    def __init__(self, store: CiFailureStore, actions: ActionsSource, *,
                 outlet: BoardOutlet | None = None, config: PipelineConfig,
                 admission: PlatformAdmission | None = None) -> None:
        if not isinstance(config, PipelineConfig):
            raise CiFailureError('Pipeline needs a PipelineConfig')
        if actions.repo != config.repository:
            raise CiFailureError('The Actions reader and the pipeline name different repositories')
        if outlet is not None:
            if outlet.board.transport is actions.transport:
                raise ScopeRefused('The board outlet must not share the Actions transport')
            if outlet.board.repo != config.repository:
                raise ScopeRefused('The board outlet and the Actions reader name different repositories')
        shared = _admitter_transport(admission) if admission is not None else None
        if shared is not None and shared is actions.transport:
            # The third outlet is the one that POSTs, and a transport in two scopes means the platform's
            # own intake route is asked of the forge: the same refusal `board`/`actions` already makes,
            # extended to the pair that actually moves verdicts. It can only see the transport a
            # `PlatformIntake` holds -- an admitter that is a bare callable or a host object of some other
            # shape is opaque here and passes unjudged, which is why this is one `is` comparison and not a
            # claim that no two outlets can ever share a socket.
            raise ScopeRefused('The platform intake must not share the Actions transport')
        self.store = store
        self.actions = actions
        self.outlet = outlet
        self.config = config
        self.admission = admission or PlatformAdmission()

    # ---- one run -> one fact ------------------------------------------------

    def _fact_for(self, run: Mapping[str, Any], now: dt.datetime) -> RunFact:
        """Read one run's jobs and log, and build its fact -- with coverage for whatever did not arrive.

        Every read failure is caught at the seam that caused it and turned into a `CoverageNote`, which
        is what makes the resulting card coarse rather than wrong. A `MalformedSource` from the *jobs*
        read is deliberately downgraded to coverage rather than propagated: the run object itself is
        still attributable evidence, and losing the failure because its job list was unreadable would
        hide main-red.
        """
        coverage: list[CoverageNote] = []
        jobs: Sequence[Mapping[str, Any]] = ()
        run_id = run.get('id')
        try:
            jobs = self.actions.jobs(run_id)
        except MalformedSource as exc:
            coverage.append(CoverageNote('job-list-malformed', str(exc)[:120]))
        except (SourceUnavailable, PaginationBudget, ScopeRefused) as exc:
            coverage.append(CoverageNote('job-list-unavailable', type(exc).__name__))
        log_text: str | None = None
        if self.actions.log_reader is not None:
            target = _failing_job(jobs, run)
            if target is None:
                coverage.append(CoverageNote('job-id-absent', 'no job object to ask about'))
            else:
                try:
                    read = self.actions.job_log(run_id, target)
                except ScopeRefused:
                    raise
                except Exception as exc:  # the seam is any callable a caller hands over
                    # A reader that raises rather than answering with a coverage sentence is a seam this
                    # pipeline does not control: `ActionsSource.job_log` swallows what its own reader
                    # raises, but a caller may hand over any callable, and the injected reader is the
                    # documented shape a caller hands over next. A failed log read is a gap in what this
                    # poller knows -- it must not end the tick that found a broken build, and it must not
                    # reach an operator as a traceback instead of an exit code. `ScopeRefused` is
                    # re-raised on purpose: a reader asked to fetch outside its allowlist is a caller bug,
                    # not a gap, and the CLI's refusal exit is the sentence for that.
                    coverage.append(CoverageNote('job-log-unreachable', type(exc).__name__))
                    read = None
                if read is not None:
                    log_text = read.excerpt
                    if read.coverage:
                        coverage.append(CoverageNote(read.coverage,
                                                     'truncated' if read.truncated else 'not-read'))
        elif self.actions.log_reader is None:
            coverage.append(CoverageNote('job-logs-not-wired'))
        # A row this parser refuses raises `RefusedRunRead`, which carries `coverage` plus whatever the
        # parser derived before it gave up: the reads happened, and the caller carries those notes even
        # though no verdict is filed here.
        return parse_run(self.config.repository, run, jobs=jobs, log=log_text, coverage=coverage,
                         main_branches=self.config.main_branches)

    def _outcome(self, fact: RunFact, now: dt.datetime) -> str:
        """`success` / a failing conclusion / `stuck` / `running`, decided once, for the whole tick.

        `stuck` is derived from a *stored* first-seen time, so the 20-minute clock survives a restart:
        `track_open_run` returns the original `waiting_since` rather than a fresh one. Reporting it once
        per run (the `stuck_reported` flag) is what keeps a starved runner at one occurrence instead of
        one per poll -- a queue of forty builds behind one dead runner is one report, not forty.
        """
        if fact.status == 'completed':
            return fact.conclusion or 'unknown'
        started = self.store.track_open_run(fact, now)
        if fact.status in QUEUED_STATUSES:
            waiting_since = started or fact.started_waiting_at or fact.created_at
            if waiting_since is not None \
                    and (now - waiting_since).total_seconds() >= self.config.stuck_after_seconds \
                    and not self.store.stuck_reported(fact.repository, fact.run_id):
                self.store.mark_stuck_reported(fact.repository, fact.run_id, now)
                return 'stuck'
            return 'waiting'
        return 'running'

    # ---- the tick -----------------------------------------------------------

    def poll_once(self, *, now: dt.datetime | None = None) -> TickReport:
        """Run one bounded poll. Returns a report; raises only for a scope refusal (a bug, not a state).

        Any transport or parse problem is reported through `TickReport.error` / `complete=False` and
        leaves the durable state consistent: the cursor points at the last page that committed, the
        facts already recorded stay recorded, and pending deliveries stay pending.
        """
        moment = now or dt.datetime.now(dt.timezone.utc)
        reconciled: ReconcileReport | None = None
        if self.outlet is not None:
            reconciled = self.outlet.reconcile(now=moment)
        if self.config.seed_cursor is not None and self.store.cursor() == 0:
            self.store.set_cursor(int(self.config.seed_cursor), moment)
        pairs: list[tuple[RunFact, Any]] = []
        outcomes: list[str] = []
        # Every run this poll parsed, new to the store or not. `pairs` is the *novel* subset (that is what
        # the filing and the board journal are for), but "is this gap still open?" is a question about this
        # poller's reads, and a run that has been sitting in the queue for an hour is re-read on every
        # tick while answering nothing new -- leave it out and the poll that reads a clean build next door
        # reports the gap it can still see as recovered. A row this poll refused to parse is in here too,
        # as a carrier with no verdict on it (`facts.coverage_only_fact`): the reads that came before the
        # refusal happened, and a gap this process met does not become unread because the run carrying it
        # was unparseable.
        read: list[RunFact] = []
        recovered: list[dict[str, Any]] = []
        # Run ids this poll asked about and did not get an answer for (the bounded refresh of the runs it
        # still calls in flight). They do not stop the walk from being `complete` -- the page came back --
        # but they do stop this poll from claiming it read everything it knows about, which is the licence a
        # gap closure runs on. See `adapter.PollRead`.
        unread: list[int] = []
        scanned = refusals = 0
        complete = True
        error: str | None = None
        started_at_cursor = self.store.cursor()
        cursor = started_at_cursor
        settled: list[int] = []
        for page in range(1, self.config.max_pages + 1):
            try:
                rows = self.actions.runs(page=page, per_page=self.config.per_page)
            except (SourceUnavailable, MalformedSource, PaginationBudget) as exc:
                error = type(exc).__name__
                complete = False
                self.store.coverage(COVERAGE_SOURCE, CoverageNote('actions-read-failed', f'page-{page}'))
                break
            scanned += len(rows)
            page_facts: list[RunFact] = []
            page_labels: list[str] = []
            reached_cursor = False
            for row in rows:
                run_id = row.get('id')
                if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
                    refusals += 1
                    self.store.refusal(self.config.repository, 'run-id-malformed',
                                       'the run object carries no positive integer id')
                    continue
                if run_id <= started_at_cursor:
                    reached_cursor = True
                    continue
                try:
                    fact = self._fact_for(row, moment)
                except MalformedSource as exc:
                    refusals += 1
                    self.store.refusal(self.config.repository, 'run-malformed', str(exc)[:200],
                                       run_id=run_id)
                    carrier = _coverage_carrier(exc, self.config.repository, run_id)
                    if carrier is not None:
                        read.append(carrier)
                    continue
                page_facts.append(fact)
                label = self._outcome(fact, moment)
                page_labels.append(label)
                if fact.status == 'completed':
                    settled.append(run_id)
                    # Read before the row goes: `drop_open_run` deletes the only record of what this run
                    # was reported as while it was waiting, and after it there is nothing to attribute a
                    # recovery to.
                    back = self._recovery(fact, label)
                    if back is not None:
                        recovered.append(back)
                    # The run has its verdict in hand, so it leaves the refresh set: a row left behind
                    # here would be asked about by GET on every later tick for nothing.
                    self.store.drop_open_run(self.config.repository, run_id)
            if page_facts:
                read.extend(page_facts)
                for fact, label_outcome in self.store.record_facts(page_facts, cursor=cursor,
                                                                   now=moment, outcomes=page_labels):
                    pairs.append((fact, card_identity(fact)))
                    outcomes.append(label_outcome)
            if len(rows) < self.config.per_page:
                break
            if reached_cursor:
                break
        else:
            complete = False
            self.store.coverage(COVERAGE_SOURCE, CoverageNote('scan-page-budget', 'history-unfinished'))
        if complete and settled:
            # The cursor moves only at the end of a walk that finished, and only up to the newest run
            # whose verdict has arrived. Mid-walk it stays put: the invariant it carries is "every run
            # newer than me has been ingested", and an aborted walk cannot claim that about the rows it
            # never reached -- nor can a completed walk claim it about a row that was still queued, because
            # the fact that matters (the verdict) does not exist yet. Counting an unfinished run here is
            # how a poller loses a failure forever: the run settles on a later tick, and `run_id <= cursor`
            # then reads it as history. Re-reading committed pages is cheap -- `runs.event_key` and
            # `occurrences(fingerprint, run_id)` turn a replay into a no-op.
            cursor = max(settled)
            self.store.set_cursor(cursor, moment)
        # The runs the walk can no longer reach are the ones this store itself remembers as open. Their
        # verdicts are fetched one bounded GET each, so a low-id run that was queued when the cursor passed
        # it still reaches the board when it fails.
        refresh = self._refresh_open_runs(moment, cursor, recovered, read, unread)
        if refresh:
            read.extend(fact for fact, _label in refresh)
            labels = [label for _fact, label in refresh]
            for fact, label_outcome in self.store.record_facts([fact for fact, _label in refresh],
                                                              cursor=cursor, now=moment,
                                                              outcomes=labels):
                pairs.append((fact, card_identity(fact)))
                outcomes.append(label_outcome)
        report_pairs = [(fact, identity) for (fact, identity), label in zip(pairs, outcomes, strict=True)
                        if label in FAILING_OUTCOMES]
        # Read once, before anything this tick can send moves it: the planner decides against these
        # markers, and `recovered[]` has to report the same instant the plan was built against rather than
        # a second read taken after this tick's own claims landed.
        markers = self.store.incident_key_states()
        # What this poll's own reading says, as opposed to what the runs it read say: whether the whole of
        # it came back, and which gaps are true of the wiring rather than of a build. `job-logs-not-wired`
        # is carried on every poll -- including one that read no runs at all, which is the tick that would
        # otherwise close a configuration gap it has no power to re-check.
        poll_read = PollRead(complete=error is None and complete and not unread,
                             coverage=() if self.actions.log_reader is not None
                             else (CoverageNote('job-logs-not-wired'),))
        receipts, plan, owed, abandoned = self._admit(pairs, outcomes, moment, markers, read,
                                                     poll_read=poll_read)
        self._state_recoveries(recovered, plan, markers)
        planned: tuple[str, ...] = ()
        drained: DrainReport | None = None
        if self.outlet is not None and report_pairs:
            planned = self.outlet.plan(report_pairs, now=moment).created
            drained = self.outlet.drain(now=moment)
        elif self.outlet is not None:
            drained = self.outlet.drain(now=moment)
        lapse = None
        if error is None:
            lapse = self.store.record_success(
                now=moment, outcome='ok' if complete else 'incomplete',
                detail={'scanned': scanned, 'recorded': len(pairs), 'refusals': refusals,
                        'cursor': cursor, 'complete': complete,
                        'pending': len(self.store.pending_deliveries()),
                        'platform_admission': 'not-configured' if not self.admission.configured
                        else 'configured'},
                deadline_seconds=self.config.heartbeat_deadline_seconds)
        return TickReport(scanned=scanned, recorded=len(pairs), refusals=refusals, cursor=cursor,
                          complete=complete, reconciled=reconciled, planned=planned, drained=drained,
                          events=len(plan.events), keys=len(plan.keys),
                          resolved=sum(1 for event in plan.events if event['status'] == 'resolved'),
                          superseded=plan.superseded, receipts=receipts, lapse=lapse,
                          pending_verdicts=owed, abandoned=abandoned,
                          recovered=tuple(recovered),
                          heartbeat=self.store.check_heartbeat(
                              now=moment,
                              deadline_seconds=self.config.heartbeat_deadline_seconds).as_dict(),
                          error=error)

    def _refresh_open_runs(self, now: dt.datetime, cursor: int,
                           recovered: list[dict[str, Any]],
                           read: list[RunFact], unread: list[int]) -> list[tuple[RunFact, str]]:
        """Re-read the unfinished runs the page walk has left behind -- at most N GETs, newest first.

        `poll_once` advances the cursor only over runs whose verdict arrived, but a run that is *newer
        than nothing* keeps falling behind: any settled run with a higher id moves the cursor past a still
        waiting one, and from then on `run_id <= cursor` skips it on every page. The store's own
        `open_runs` rows are the only list that still names it, and `/runs/{id}` is the only read cheap
        enough to ask about each one. Two properties this must not lose:

        * **Bounded.** `max_open_run_refresh` GETs per tick, newest first, and nothing else: a poller that
          lost a page of history must not answer by scanning the whole repository.
        * **Not a second incident.** A refreshed fact goes through `record_facts` with the cursor unchanged
          (never backwards), so a still-waiting run re-reports nothing, and a run that settled while
          waiting had its placeholder `stuck` occurrence replaced by its verdict there.

        A vanished run (404) is dropped from `open_runs` with a coverage note, so the budget is not spent
        on it every tick forever; an unreadable one keeps its row and is asked again next tick.

        `recovered` and `read` are the two lists this walk contributes to in place: the recoveries it can
        attribute, and every fact (or refused row's notes) it read, which is what the gap-closure question
        is asked of. A row here that this parser refused carries its notes and no verdict -- see
        `_coverage_carrier`.

        `unread` is the third: the runs this poll *asked* about and got no answer for -- a GET that failed,
        an answer that named a different run. A vanished run is not in it (404 is an answer, and the row is
        dropped), and a refused row is not in it either, because that one arrives as a `read_complete=False`
        carrier and the planner counts it there. What the list says is "this poll does not know what it did
        not read", and that is enough to withhold the licence a run-less poll would otherwise use to close a
        gap it never re-checked.
        """
        reader = getattr(self.actions, 'run', None)
        if not callable(reader):
            return []
        pending = sorted((run_id for run_id in self.store.open_run_ids(self.config.repository)
                          if run_id <= cursor), reverse=True)
        facts: list[tuple[RunFact, str]] = []
        for run_id in pending[: self.config.max_open_run_refresh]:
            try:
                run = reader(run_id)
            except (SourceUnavailable, MalformedSource, PaginationBudget) as exc:
                self.store.coverage(COVERAGE_SOURCE, CoverageNote(
                    'open-run-refresh-failed', f'{run_id}:{type(exc).__name__}'))
                unread.append(run_id)
                continue
            if run is None:
                self.store.coverage(COVERAGE_SOURCE,
                                    CoverageNote('open-run-vanished', f'{run_id}:gone-from-the-forge'))
                self.store.drop_open_run(self.config.repository, run_id)
                continue
            try:
                fact = self._fact_for(run, now)
            except MalformedSource as exc:
                self.store.refusal(self.config.repository, 'run-malformed', str(exc)[:200], run_id=run_id)
                carrier = _coverage_carrier(exc, self.config.repository, run_id)
                if carrier is not None:
                    read.append(carrier)
                continue
            if fact.run_id != run_id:
                self.store.coverage(COVERAGE_SOURCE,
                                    CoverageNote('open-run-id-mismatch', f'{run_id}:{fact.run_id}'))
                unread.append(run_id)
                continue
            label = self._outcome(fact, now)
            if fact.status == 'completed':
                back = self._recovery(fact, label)
                if back is not None:
                    recovered.append(back)
                self.store.drop_open_run(self.config.repository, run_id)
            facts.append((fact, label))
        return facts

    def _recovery(self, fact: RunFact, outcome: str) -> dict[str, Any] | None:
        """One run this store had told somebody about as starved, arriving with a non-failing verdict.

        The `open_runs` row is what knows: `stuck_reported` is the flag that folded a starved-runner storm
        into one report, and the row is deleted the moment a run settles, so this call -- made before the
        drop -- is the one instant at which the recovery can still be attributed to the report that opened
        it. A run that was merely `waiting` never opened anything, so it recovers quietly and is not
        named here; a run that was starved and then *failed* is not a recovery either, and says so by
        staying out of this list.

        It sends nothing and writes nothing. The `incident_key` it carries is what `poll_once` matches
        against the plan's closures once the events exist, so the `incident_statement` below reports an
        offer this tick really made rather than a hope; until then it says the plain thing.
        """
        if fact.status != 'completed' or outcome in FAILING_OUTCOMES:
            return None
        if not self.store.stuck_reported(fact.repository, fact.run_id):
            return None
        return {'repository': fact.repository, 'run_id': fact.run_id, 'was_reported': 'stuck',
                'outcome': outcome or 'unknown', 'incident_key': incident_key(fact),
                'incident_statement': {'sent': False, 'reason': 'not-yet-offered'}}

    @staticmethod
    def _state_recoveries(recovered: Sequence[dict[str, Any]], plan: IncidentKeyPlan,
                          markers: Mapping[str, Mapping[str, Mapping[str, int]]] | None = None) -> None:
        """Say, per recovery, what the plan actually handed the platform about that incident.

        Four answers, each read off something that exists: a `resolved` was offered for this key
        (`sent: True`, and whether the platform closed anything is the receipt's answer, not this one);
        the starvation was recorded under `unknown` because it happened on a pull request, so there was
        never an incident to close; the marker this source kept still says the key is open but this poll
        closed nothing (`open-not-closed`, which is what a refused closure and a hand-closed incident
        look like from here); or no marker under this key says anything is open at all (`nothing-known-open`
        -- a run whose starvation was never offered to the platform, which after the receipt-driven claim
        is a state that can actually happen again).
        """
        held = markers or {}
        for entry in recovered:
            key = str(entry.get('incident_key') or '')
            pair = (key, RULE_STUCK)
            if pair in plan.resolved_rules:
                entry['incident_statement'] = {'sent': True, 'reason': 'resolved-offered'}
            elif pair in plan.recorded_rules:
                entry['incident_statement'] = {'sent': False, 'reason': 'recorded-not-opened'}
            elif int(((held.get(key) or {}).get(RULE_STUCK) or {}).get('open') or 0) > 0:
                entry['incident_statement'] = {'sent': False, 'reason': 'open-not-closed'}
            else:
                entry['incident_statement'] = {'sent': False, 'reason': 'nothing-known-open'}

    def _admit(self, pairs: Sequence[tuple[RunFact, Any]], outcomes: Sequence[str],
               now: dt.datetime, markers: Mapping[str, Mapping[str, Mapping[str, int]]],
               read: Sequence[RunFact] = (),
               poll_read: PollRead | None = None
               ) -> tuple[tuple[AdmissionReceipt, ...], IncidentKeyPlan, int, tuple[dict[str, Any], ...]]:
        """Offer this tick's verdicts plus whatever is still owed, and move markers only on an answer.

        The candidates are the facts that speak about a key at all: a failing or starved one (which may
        open an incident) and a completed-green one (which may close one). Everything else -- a run still
        in flight under its waiting label, say -- is deliberately absent, because handing the planner a
        fact nobody paged on and never resolved would have it fire on load. `read` is the wider set: every
        run this poll parsed, which is what the *coverage* question is asked of, because a gap in this
        poller's own reads is not a verdict about anybody's build.

        The markers are read from the store and recomputed here, so the plan stays a pure function of
        (these facts, those markers, what is owed): a re-run of the same tick with the same state
        recomputes the same events. What it writes back is decided *after* the send, from the receipts --
        `claim_transitions` returns the marker moves the platform actually took. A verdict it never took
        is kept in `verdicts_pending` and offered again on a later tick, because the fact behind it is
        behind the cursor by then and nothing else would ever say it again. That table, not this object's
        memory, is what makes "the platform has this" mean the platform has it.

        Three writes, in this order, and the order is the durability argument: retire what can no longer
        converge, write the owed row for everything about to be offered, send, then claim the markers and
        retire those rows in one commit. See the notes in the body.

        Two kinds of verdict are never owed, for opposite reasons: a pull-plane `unknown`, because it opens
        nothing and so owes nobody a page, and a *coverage closure*, because unlike a workflow verdict it is
        re-derivable -- see `_is_coverage_closure`. What `poll_read` licenses is what makes that safe on a
        repository that stops building: a poll that read its source cleanly and no longer carries the reason
        says so again on every tick until something answers, and one that could not read its source says
        nothing -- which is the sentence that used to be true only while somebody kept pushing.

        Returns the receipts, the plan including anything re-offered from the pending table, how many
        verdicts are still owed after this tick, and the rows this tick gave up on.
        """
        candidates = [fact for (fact, _identity), label in zip(pairs, outcomes, strict=True)
                      if label in FAILING_OUTCOMES
                      or (fact.status == 'completed' and fact.conclusion == GREEN_CONCLUSION)]
        abandoned = [dict(entry) for entry in self.store.expire_pending_verdicts(now=now)]
        waiting = self.store.pending_verdicts()
        open_gaps = {rule_id for rule_id, rung in (markers.get(COVERAGE_SUBJECT) or {}).items()
                     if int(rung.get('open') or 0)}
        # A tick with nothing to judge, nothing owed and nothing read has nothing to say -- except about an
        # open coverage marker on a repository that has gone quiet. There the closure cannot be re-derived
        # from a run, because there is no new run to read, and the poll's own clean read is the only
        # evidence available (`adapter.PollRead`). Skipping the plan here is what left such a gap open
        # forever with the exit code clean and nothing owed.
        if (not candidates and not waiting and not read
                and not (open_gaps and poll_read is not None and poll_read.complete)):
            # `_mark_reoffered` reads the plan, and this plan is empty by construction: a poll that emitted
            # no events at all neither re-filed nor withdrew anything, so both words are false on every row
            # the ceilings retired above. That is the answer, not an oversight -- hence the plan object
            # rather than a bare `frozenset()` at the call.
            return (), IncidentKeyPlan(), 0, _mark_reoffered(abandoned, IncidentKeyPlan())
        plan = plan_incident_keys(candidates, markers, now=now, read_facts=tuple(read),
                                  pending={key: {rule_id: int(row.get('open_run') or 0)
                                                 for rule_id, row in rules.items()}
                                           for key, rules in waiting.items()},
                                  poll_read=poll_read)
        # A stored verdict the plan has just spoken about again is superseded by that newer word, so only
        # what the plan left alone travels a second time. Rows the plan cannot speak about are judged here
        # rather than in a comprehension, because one shape is judged by what this poll read rather than
        # replayed: a coverage *closure* in the table says "this poller's reads came back", and only this
        # poll can say whether that is still true.
        replay: list[tuple[str, str, dict[str, Any]]] = []
        retired: list[dict[str, Any]] = []
        refused_rows = any(not fact.read_complete for fact in read)
        for subject, rules in sorted(waiting.items()):
            for rule_id, row in sorted(rules.items()):
                if (subject, rule_id) in plan.spoken or not isinstance(row.get('event'), Mapping):
                    continue
                if _is_coverage_closure(subject, row['event']):
                    if rule_id in plan.carried:
                        # The gap is back in this poll's hands, so the stored word about it is a lie: this
                        # is the shape round 3 graded a blocker for -- a `resolved` the platform books for a
                        # gap the source is reading. The row is retired, never sent.
                        retired.append(_retired_row(subject, rule_id, row,
                                                    'a coverage closure for a gap this poll is reading'))
                    elif poll_read is None or not poll_read.complete or refused_rows:
                        # This poll could not read its whole source, or left a row unparsed: it neither
                        # knows the gap healed nor knows the closure lies, so it neither sends the row nor
                        # gives up on it. An offer this poll cannot stand behind is not worth an attempt
                        # counter, and the two ceilings still bound the wait.
                        continue
                    else:
                        # Nothing this poll read carries the gap and the read came back, so the closure is
                        # true. When the marker still says open the plan spoke it above and this row is
                        # gone; reaching here means the marker is not there -- an older build's row, or one
                        # left behind by the upgrade recipe -- and this row is the only true statement
                        # available about an incident the platform may still be holding.
                        replay.append((subject, rule_id, row))
                    continue
                replay.append((subject, rule_id, row))
        abandoned.extend(retired)
        # The owed row is written *before* the send, for every verdict the poll is about to offer, not only
        # for the ones that come back refused. A row created after a refused answer is a promise made in the
        # same breath as the failure that breaks it: anything that stops this process between the send and
        # that write -- a store that raises on the way back from a platform that already took the event, a
        # SIGKILL, a filesystem full at the wrong instant -- leaves the platform holding an incident this
        # source has no record of owing, while the fact behind it sits behind the cursor and will never be
        # re-read. Written first, the worst case is a row that is replayed and answered `duplicate`, which
        # is an answer and converges. The reason on the row is the placeholder the send has not yet earned.
        offered: dict[tuple[str, str], dict[str, Any]] = {}
        for claim in plan.claims:
            # A pull-request build is filed under `PULL_STATUS` and opens nothing, so a refusal there costs
            # a row in the platform's own event table and not a page nobody would be sent. It is not owed,
            # and neither is a coverage closure: `poll_read` re-derives that on every poll whose own read
            # came back -- a poll that read a clean run, or a poll the quiet repository left nothing to
            # read -- so a row would add nothing except the risk of being said on a tick that cannot stand
            # behind it.
            if (plan.events[claim.index].get('status') == PULL_STATUS
                    or _is_coverage_closure(claim.key, plan.events[claim.index])):
                continue
            offered[(claim.key, claim.rule_id)] = _owed_row(claim.key, claim.rule_id,
                                                            plan.events[claim.index], claim.open_run,
                                                            claim.closed_run, UNANSWERED)
        for subject, rule_id, row in replay:
            offered[(subject, rule_id)] = _owed_row(subject, rule_id, row['event'], row.get('open_run'),
                                                    row.get('closed_run'), UNANSWERED)
        if offered:
            # `attempts` counts offers a platform could have answered, not polls this process ran. With no
            # platform wired the row is still written -- `--status` has to say what is owed, and a row that
            # exists before the send is the durability argument above -- but it is written uncounted, so an
            # unwired poller keeps its backlog for the ramp-up the docs recommend instead of abandoning an
            # hour of breaks as "offered twelve times and never taken" to a platform that never existed.
            # The evidence-lifetime ceiling still applies: that one is about the event, not about wiring.
            #
            # A backlog bigger than the table bound is decided here, in this transaction, on rows this poll
            # did not hand over -- so the write answers with them and they are reported, not subtracted from
            # a count that then reads steady at the bound while pages leave.
            abandoned.extend(self.store.record_pending_verdicts(
                list(offered.values()), now=now, counted=self.admission.configured).evicted)
        receipts = tuple(self.admission.admit(plan.events + tuple(row['event']
                                                                  for _s, _r, row in replay)))
        owed: list[dict[str, Any]] = []
        settled: set[tuple[str, str]] = set()
        claims = list(claim_transitions(plan, receipts)) + list(claimed_coverage_moves(plan, receipts))
        for claim in plan.claims:
            pair = (claim.key, claim.rule_id)
            answered = claim.index < len(receipts) and receipts[claim.index].admitted
            if answered:
                settled.add(pair)
            elif _is_coverage_closure(claim.key, plan.events[claim.index]):
                # The closure was refused, so nothing is kept: the marker still says the gap is open (the
                # claim that would have cleared it is driven by this receipt), and the next poll whose own
                # read came back -- a poll that reads a clean run, or a poll the quiet repository leaves
                # nothing to read -- says the same thing again with a window that is true of *that* poll.
                # Keeping the row would make the next poll owe a recovery it may not be entitled to speak
                # (the gap may be back), which is the harm `_is_coverage_closure` spells out. Retiring the
                # pair also clears whatever firing row it held, which this closure superseded.
                settled.add(pair)
            elif plan.events[claim.index].get('status') != PULL_STATUS:
                reason = (receipts[claim.index].reason if claim.index < len(receipts)
                          else 'the platform never answered')
                owed.append(_owed_row(claim.key, claim.rule_id, plan.events[claim.index],
                                      claim.open_run, claim.closed_run, reason))
            else:
                settled.add(pair)
        replayed = receipts[len(plan.events):]
        for (subject, rule_id, row), receipt in zip(replay, replayed, strict=True):
            if receipt.admitted:
                settled.add((subject, rule_id))
                claims.append(KeyTransition(subject, rule_id, row.get('open_run'),
                                            row.get('closed_run')))
            else:
                owed.append(_owed_row(subject, rule_id, row['event'], row.get('open_run'),
                                      row.get('closed_run'), receipt.reason))
        # One commit for both halves of the same answer: the markers the receipts justified, and the owed
        # rows those same receipts retired. Split across two transactions, a failure in between claims an
        # incident the table still says is owed (and the next tick offers it a second time to a platform
        # that has it), or retires a row whose marker never landed (and then no green run can ever close
        # the incident, because the closure rule reads `open` and finds nothing open).
        # The stale closures ride the same commit: they are owed rows this poll has decided to retire, and
        # a row that is neither offered nor dropped would pin `pending_verdicts` until its evidence expired.
        settled.update((str(entry['key']), str(entry['rule_id'])) for entry in retired)
        if claims or settled:
            self.store.record_incident_keys(claims, now=now, drop=sorted(settled))
        if owed:
            # The rows are already on disk -- the pre-send write offered them, and `attempts` counted that.
            # This pass only replaces the placeholder with the answer the platform actually gave, so it must
            # not count as a second offer to a platform that was asked once. The restatement can push the
            # table over its bound too (a refused backlog that grew this tick), and the rows it evicts are
            # named in the same report field.
            abandoned.extend(self.store.record_pending_verdicts(owed, now=now, counted=False).evicted)
        if replay:
            base = len(plan.events)
            # `spoken` names every pair this poll emitted an event about, and a replayed row is one: the
            # returned plan carries its own events, so the field is recomputed rather than left at the
            # planner's answer, which no longer describes `events`/`claims`.
            plan = replace(plan, events=plan.events + tuple(row['event'] for _s, _r, row in replay),
                           claims=plan.claims + tuple(EventClaim(base + index, subject, rule_id,
                                                                 open_run=row.get('open_run'),
                                                                 closed_run=row.get('closed_run'))
                                                      for index, (subject, rule_id, row)
                                                      in enumerate(replay)),
                           spoken=plan.spoken | {(subject, rule_id) for subject, rule_id, _row in replay})
        # A row retired above cannot be replayed this tick (it was deleted before `waiting` was read), so
        # "will this poll say it anyway?" is exactly "did the planner speak about that pair, and which way?":
        # a gap this poll still reads is filed again as a fresh firing, a pair it just resolved is withdrawn,
        # and a verdict about a run behind the cursor is gone. Say which of the three happened rather than
        # let the report claim a page on a tick that was cancelling one.
        return (receipts, plan, self.store.pending_verdict_count(), _mark_reoffered(abandoned, plan))

    # ---- liveness -----------------------------------------------------------

    def check_liveness(self, *, now: dt.datetime | None = None) -> dict[str, Any]:
        """The read-only heartbeat answer, for the separate monitor process. Writes nothing, ever."""
        moment = now or dt.datetime.now(dt.timezone.utc)
        return self.store.check_heartbeat(now=moment,
                                          deadline_seconds=self.config.heartbeat_deadline_seconds).as_dict()


@dataclass(frozen=True)
class Service:
    """The wired object graph. `build_service` is the only place credentials are ever looked at."""
    store: CiFailureStore
    actions: ActionsSource
    board: BoardClient | None
    outlet: BoardOutlet | None
    pipeline: Pipeline
    config: PipelineConfig

    def close(self) -> None:
        self.store.close()


def _admitter_transport(admission: PlatformAdmission) -> Any:
    """The transport behind an admitter, when there is one to see, or None.

    `PlatformAdmission` is deliberately callable-shaped -- the host hands it any `admit` callable -- so the
    only admitter whose transport can be named is this package's own `PlatformIntake`, reached through the
    bound method's `__self__`. Anything else returns None and is left unjudged: a check that cannot see a
    shared transport must not claim to have looked.
    """
    admitter = getattr(admission, 'admitter', None)
    intake = getattr(admitter, '__self__', None)
    return getattr(intake, 'transport', None)


#: The reason an owed row carries between the write that offered it and the answer that came back. It is
#: never a refusal, and it is what an operator reads if the process died with a send in flight.
UNANSWERED = 'offered, no answer read back'


def _owed_row(key: str, rule_id: str, event: Mapping[str, Any], open_run: Any, closed_run: Any,
              reason: str) -> dict[str, Any]:
    """The pending-table row for one verdict the platform never took.

    It carries the event verbatim plus the marker move that event was going to make, because a later poll
    has to be able to both re-offer the verdict and honour the claim it carries -- and it carries `reason`
    so an operator reading the table back can see why it is still there.
    """
    return {'key': key, 'rule_id': rule_id, 'event': dict(event),
            'open_run': None if open_run is None else int(open_run),
            'closed_run': None if closed_run is None else int(closed_run),
            'reason': str(reason or '')[:200]}


def _is_coverage_closure(subject: str, event: Mapping[str, Any]) -> bool:
    """Whether one verdict is the *closure* of a gap in this poller's own reads.

    A workflow verdict is owed until it lands: the fact behind it is behind the cursor, so a poll that
    decided "main is red" and lost the answer has no other way to ever say it again. A coverage closure
    is the opposite case. It is derived every poll from two things that keep their own state -- the marker
    that says the gap is open, and this poll's reads saying the gap is gone -- so a refused closure is
    *re-derived* by the next poll whose own read came back, with a window that is true of that poll: the
    licence is `adapter.PollRead`, which a poll that found no new run to read still holds (and which a poll
    whose fetch failed, or whose rows were all refused, does not).

    Owing the row for the *closure this poll just spoke* is what is wrong, because the plan says nothing
    about a gap the poll is carrying (filing it would churn an open condition, closing it would lie) and a
    stored `resolved` replayed on that tick would travel as "read again" for a gap this poll has in hand --
    the platform books a recovery that did not happen, the operator is re-paged when the gap re-fires, and
    the marker is cleared from the replayed receipt, so this source forgets a gap it is still reading.
    `_admit` therefore judges a stored closure against this poll's own read: carried, and the row is retired
    and named in the report; not readable, and the row waits; otherwise it travels, which is the only way a
    closure left behind by an older build -- or one whose marker the upgrade recipe deleted -- reaches the
    platform at all.

    `COVERAGE_SUBJECT` is the reserved subject a gap marker lives under (`adapter.py`), and a coverage
    *firing* stays owed: a firing refused by the platform has no marker, and if the gap then heals the
    closure this poll speaks retires that pair -- see `_admit`.
    """
    return subject == COVERAGE_SUBJECT and str(event.get('status') or '') == 'resolved'


def _retired_row(subject: str, rule_id: str, row: Mapping[str, Any],
                 reason: str) -> dict[str, Any]:
    """One owed row this poll took off the table without sending it, in `abandoned[]`'s shape.

    `store.expire_pending_verdicts` builds this shape for the rows its ceilings retire; this is the same
    promise for the rows *this poll* retired, for the same reason: a row that leaves the owed table is a
    page this source will not send, and it has to be named in the report rather than subtracted from a
    count. `decided_at` is the poll that decided the verdict, which is the one a reader should look at.
    """
    return {'key': subject, 'rule_id': rule_id, 'reason': reason,
            'attempts': int(row.get('attempts') or 1), 'decided_at': str(row.get('at') or ''),
            'event_status': str(row['event'].get('status') or '')}


def _mark_reoffered(entries: list[dict[str, Any]],
                    plan: IncidentKeyPlan) -> tuple[dict[str, Any], ...]:
    """Put the honest word on each row this tick gave up on, and hand the tuple to the report.

    `abandoned` is the counterparty of "we still owe it", and the retirement is written before the plan
    exists. Three different things can have happened to a pair, and the reader cannot tell them from the
    row alone, so this says which -- by looking up the *status* this poll emitted for the same
    `(key, rule_id)`:

    * nothing spoken -- the row is gone and the page with it (`reoffered` and `withdrawn` both false);
    * a `firing` -- the condition is being said again right now, which is what a gap this poll is still
      reading looks like: the bound deleted the row that was telling the planner it had already been said,
      so the report would otherwise say "a page that will not be sent" on a tick that is sending it;
    * a `resolved` (or a pull-plane `unknown`, which opens nothing) -- the owed verdict is *withdrawn*: a
      newer word about that pair left this process, so the firing will not travel, but calling that
      `reoffered` would report a repeat of a page the same poll cancelled.

    Matching on the pair alone is what made the old field read wrong in that last case, which is why this
    takes the plan and not its `spoken` set.

    One entry per `(key, rule_id)`: the table bound can drop a row in the write made before the send and
    drop the same pair again in the restatement made after it, and a report that named the verdict twice
    would read like two pages were lost.
    """
    statuses: dict[tuple[str, str], str] = {}
    for claim in plan.claims:
        if 0 <= claim.index < len(plan.events):
            statuses[(claim.key, claim.rule_id)] = str(plan.events[claim.index].get('status') or '')
    reported: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in entries:
        pair = (str(entry.get('key') or ''), str(entry.get('rule_id') or ''))
        status = statuses.get(pair)
        entry['reoffered'] = status == 'firing'
        entry['withdrawn'] = status in ('resolved', PULL_STATUS)
        reported.setdefault(pair, entry)
    return tuple(reported.values())


def _coverage_carrier(exc: BaseException, repository: str, run_id: Any) -> RunFact | None:
    """The notes a refused run carried, as a carrier for this poll's read set -- or None.

    Two cases answer "nothing to carry": a `MalformedSource` raised by a read that never got as far as
    `parse_run` (it names no gaps), and a row this poll could not attribute to a positive run id -- a
    note with nothing to attribute it to is not knowledge a later tick can act on. Either way the refusal
    row is written and the walk continues; this is only about what the closure rule is allowed to forget.
    """
    notes = tuple(getattr(exc, 'coverage', ()) or ())
    if not notes:
        return None
    try:
        return coverage_only_fact(repository, run_id, notes)
    except CiFailureError:
        return None


def _integer(environ: Mapping[str, str], name: str, default: int, *, low: int, high: int) -> int:
    """Read one bounded integer from the environment, refusing a typo instead of defaulting past it.

    An operator who writes `LO_CI_STUCK_AFTER_SECONDS=fifteen` must get a startup failure that names the
    variable, not a silently-ignored value: the alternative is a starved-runner watch that nobody knows
    is off.
    """
    raw = environ.get(name)
    if raw is None or raw == '':
        return int(default)
    try:
        value = int(raw.strip())
    except (TypeError, ValueError):
        raise CiFailureError(f'{name} must be an integer') from None
    if not low <= value <= high:
        raise CiFailureError(f'{name} must be between {low} and {high}')
    return value


def environment_config(environ: Mapping[str, str], *, repository: str | None = None,
                       state_dir: Path | str | None = None) -> tuple[PipelineConfig, Path]:
    """Build the configuration from *environ* only, and name the state file it implies.

    Every value is bounded here rather than at its point of use. Nothing here reads a credential: the
    environment carries a *token file path*, and the credential itself is read later, by the transport
    that needs it, through `local_observe.credentials`.
    """
    repo = repository or environ.get('LO_CI_REPOSITORY') or ''
    thresholds = Thresholds(
        occurrences=_integer(environ, 'LO_CI_CARD_OCCURRENCES', 3, low=1, high=1000),
        distinct_shas=_integer(environ, 'LO_CI_CARD_DISTINCT_SHAS', 2, low=1, high=1000),
        window_days=_integer(environ, 'LO_CI_CARD_WINDOW_DAYS', 7, low=1, high=7),
        labels=tuple(part.strip() for part in (environ.get('LO_CI_CARD_LABELS')
                                               or 'aiops,audit-finding').split(',') if part.strip()))
    config = PipelineConfig(
        repository=repo,
        main_branches=tuple(part.strip() for part in (environ.get('LO_CI_MAIN_BRANCHES')
                                                      or 'main,master').split(',') if part.strip()),
        stuck_after_seconds=_integer(environ, 'LO_CI_STUCK_AFTER_SECONDS',
                                     DEFAULT_STUCK_AFTER_SECONDS, low=60, high=86400),
        heartbeat_deadline_seconds=_integer(environ, 'LO_CI_HEARTBEAT_DEADLINE_SECONDS',
                                            DEFAULT_HEARTBEAT_DEADLINE_SECONDS, low=60, high=86400),
        max_pages=_integer(environ, 'LO_CI_MAX_PAGES', 20, low=1, high=20),
        per_page=_integer(environ, 'LO_CI_PER_PAGE', 50, low=1, high=50),
        max_open_run_refresh=_integer(environ, 'LO_CI_MAX_OPEN_RUNS', 20, low=0, high=50),
        file_cards=str(environ.get('LO_CI_FILE_CARDS', 'off')).strip().lower() in ('1', 'true', 'on',
                                                                                  'yes'),
        thresholds=thresholds,
        run_link_base=environ.get('LO_CI_RUN_LINK_BASE', ''),
        seed_cursor=None if not environ.get('LO_CI_SEED_CURSOR')
        else _integer(environ, 'LO_CI_SEED_CURSOR', 0, low=0, high=2 ** 62))
    directory = Path(state_dir or environ.get('LO_CI_STATE_DIR') or './ci-failures')
    return config, directory / 'ci-failures.sqlite3'


def build_service(*, config: PipelineConfig, state_path: Path | str,
                  actions_transport: Any | None = None, board_transport: Any | None = None,
                  actions_client: Any | None = None, board_client: Any | None = None,
                  log_reader: Any | None = None, admission: PlatformAdmission | None = None,
                  file_cards: bool | None = None) -> Service:
    """Assemble the real service graph, with transports injected or built from mounted credentials.

    Tests call this with two fake transports and get the same object graph a deployment gets: the
    GET-only reader, the separately scoped board client, the outlet over it, the pipeline over both.
    Passing one transport for both is not a mistake this function can be talked into hiding --
    `Pipeline` refuses it -- and passing neither builds nothing that could write: with no board client
    the service comes back with `outlet=None`, plans nothing, and says so.

    `file_cards` overrides the configuration switch. Off (the default in `environment_config`) means
    the outlet reconciles and reports but never writes, so a first deployment proves its routing before
    it touches the board.
    """
    store = CiFailureStore(state_path)
    actions = ActionsSource(actions_transport or _transport(actions_client, 'LO_CI_ACTIONS'),
                            config.repository, log_reader=log_reader, per_page=config.per_page)
    resolved = replace(config, file_cards=config.file_cards if file_cards is None else bool(file_cards))
    outlet: BoardOutlet | None = None
    board: BoardClient | None = None
    if board_transport is not None or board_client is not None:
        board = BoardClient(board_transport or _transport(board_client, 'LO_CI_BOARD'),
                            resolved.repository, per_page=resolved.per_page)
        outlet = BoardOutlet(store, board, config=OutletConfig(
            thresholds=resolved.thresholds, file_cards=resolved.file_cards,
            run_link_base=resolved.run_link_base))
    pipeline = Pipeline(store, actions, outlet=outlet, config=resolved, admission=admission)
    return Service(store=store, actions=actions, board=board, outlet=outlet, pipeline=pipeline,
                   config=resolved)


def _transport(client: Any, prefix: str) -> HttpJsonTransport:
    """Wrap a `http.JsonClient` for one credential scope, reading only `<PREFIX>_TOKEN(_FILE)`."""
    from local_observe.credentials import read_credential
    from local_observe.http import JsonClient

    if client is None:
        raise CiFailureError(f'{prefix}_CLIENT or a mounted {prefix}_TOKEN_FILE is required')
    if isinstance(client, str):
        token = read_credential(prefix + '_TOKEN')
        client = JsonClient(client, token, scheme='token')
    return HttpJsonTransport(client)


def _failing_job(jobs: Sequence[Mapping[str, Any]], run: Mapping[str, Any]) -> int | None:
    """The first job that failed, else the first job at all -- the log we ask for is one job's.

    Falls back to the run-level `workflow_jobs` array when the jobs endpoint was unreadable, so a run
    whose job list arrived inline can still have its log read rather than being written off.
    """
    candidates: list[Mapping[str, Any]] = list(jobs) or [
        job for job in (run.get('workflow_jobs') or run.get('jobs') or [])
        if isinstance(job, Mapping)]
    for job in candidates:
        if job.get('conclusion') in ('failure', 'cancelled', 'timed_out', 'action_required'):
            job_id = job.get('id')
            if isinstance(job_id, int) and not isinstance(job_id, bool) and job_id > 0:
                return job_id
    for job in candidates:
        job_id = job.get('id')
        if isinstance(job_id, int) and not isinstance(job_id, bool) and job_id > 0:
            return job_id
    return None

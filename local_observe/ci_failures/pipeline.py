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
it monitors cannot observe that the thing stopped, which is exactly the defect the review named.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import datetime as dt
from pathlib import Path
from typing import Any
from collections.abc import Mapping, Sequence

from local_observe.log import get_logger
from .adapter import AdmissionReceipt, PlatformAdmission, build_events
from .facts import (CoverageNote, DEFAULT_MAIN_BRANCHES, RunFact, card_identity, parse_run)
from .outlet import BoardOutlet, DrainReport, OutletConfig, ReconcileReport, Thresholds
from .store import FAILING_OUTCOMES, CiFailureStore
from .transports import (ActionsSource, BoardClient, CiFailureError, HttpJsonTransport, MalformedSource,
                         PaginationBudget, ScopeRefused, SourceUnavailable)

log = get_logger(__name__)

__all__ = ['Pipeline', 'PipelineConfig', 'Service', 'TickReport', 'build_service', 'environment_config',
           'COVERAGE_SOURCE', 'DEFAULT_HEARTBEAT_DEADLINE_SECONDS', 'DEFAULT_STUCK_AFTER_SECONDS']
#: The starved-runner class the card names (2026-08-21): a run that has not started for 20 minutes.
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
    """One tick's answer, in a shape a log line, a report or a test can read."""
    scanned: int = 0
    recorded: int = 0
    refusals: int = 0
    cursor: int = 0
    complete: bool = True
    reconciled: ReconcileReport | None = None
    planned: tuple[str, ...] = ()
    drained: DrainReport | None = None
    events: int = 0
    receipts: tuple[AdmissionReceipt, ...] = ()
    lapse: dict[str, Any] | None = None
    heartbeat: dict[str, Any] | None = None
    error: str | None = None

    @property
    def admitted(self) -> int:
        return sum(1 for receipt in self.receipts if receipt.admitted)

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
                'planned': list(self.planned), 'events': self.events,
                'platform_admission': self.platform_admission,
                'admitted': self.admitted, 'refused': self.events - self.admitted,
                'reconciled': None if self.reconciled is None else self.reconciled.as_dict(),
                'drained': None if self.drained is None else self.drained.as_dict(),
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
                read = self.actions.job_log(run_id, target)
                log_text = read.excerpt
                if read.coverage:
                    coverage.append(CoverageNote(read.coverage,
                                                 'truncated' if read.truncated else 'not-read'))
        elif self.actions.log_reader is None:
            coverage.append(CoverageNote('job-logs-not-wired'))
        return parse_run(self.config.repository, run, jobs=jobs, log=log_text, coverage=coverage,
                         main_branches=self.config.main_branches)

    def _outcome(self, fact: RunFact, now: dt.datetime) -> str:
        """`success` / a failing conclusion / `stuck` / `running`, decided once, for the whole tick.

        `stuck` is derived from a *stored* first-seen time, so the 20-minute clock survives a restart:
        `track_open_run` returns the original `waiting_since` rather than a fresh one. Reporting it once
        per run (the `stuck_reported` flag) is what keeps a starved runner at one occurrence instead of
        one per poll -- the fold the card's storm clause asks for.
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
                    continue
                page_facts.append(fact)
                page_labels.append(self._outcome(fact, moment))
                if fact.status == 'completed':
                    settled.append(run_id)
                    # The run has its verdict in hand, so it leaves the refresh set: a row left behind
                    # here would be asked about by GET on every later tick for nothing.
                    self.store.drop_open_run(self.config.repository, run_id)
            if page_facts:
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
        refresh = self._refresh_open_runs(moment, cursor)
        if refresh:
            labels = [label for _fact, label in refresh]
            for fact, label_outcome in self.store.record_facts([fact for fact, _label in refresh],
                                                              cursor=cursor, now=moment,
                                                              outcomes=labels):
                pairs.append((fact, card_identity(fact)))
                outcomes.append(label_outcome)
        report_pairs = [(fact, identity) for (fact, identity), label in zip(pairs, outcomes, strict=True)
                        if label in FAILING_OUTCOMES]
        receipts, events = self._admit(report_pairs, moment)
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
                          events=len(events), receipts=receipts, lapse=lapse,
                          heartbeat=self.store.check_heartbeat(
                              now=moment,
                              deadline_seconds=self.config.heartbeat_deadline_seconds).as_dict(),
                          error=error)

    def _refresh_open_runs(self, now: dt.datetime,
                           cursor: int) -> list[tuple[RunFact, str]]:
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
                continue
            if fact.run_id != run_id:
                self.store.coverage(COVERAGE_SOURCE,
                                    CoverageNote('open-run-id-mismatch', f'{run_id}:{fact.run_id}'))
                continue
            label = self._outcome(fact, now)
            if fact.status == 'completed':
                self.store.drop_open_run(self.config.repository, run_id)
            facts.append((fact, label))
        return facts

    def _admit(self, pairs: Sequence[tuple[RunFact, Any]],
               now: dt.datetime) -> tuple[tuple[AdmissionReceipt, ...], list[dict[str, Any]]]:
        """Build the canonical events and hand them over. Never decides anything itself."""
        events: list[dict[str, Any]] = []
        for fact, identity in pairs:
            events.extend(build_events(fact, identity, now=now))
        if not events:
            return (), []
        return tuple(self.admission.admit(events)), events

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

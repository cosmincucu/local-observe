"""What a CI run *is*, once read: strict parsing, then the two identities that decide everything.

Two identities, deliberately different, because they answer different questions:

* **Event identity** (`event_identity`) answers "have I already seen *this* build?" and therefore
  **includes** `head_sha`: the push build and the PR build of one commit collapse into one event,
  while two commits of the same job never do. `run_id`, `run_number` and `attempt` are excluded -- a
  re-run is the same fact seen twice, and an identity that moves on a re-run produces a second
  incident per click.
* **Card fingerprint** (`card_identity`) answers "is this the same *problem*?" and therefore
  **excludes** `head_sha`: `(repository, workflow, job, first failing step, normalised error hash)`,
  so recurrence across commits and PRs aggregates onto one card. When the step or the log excerpt
  never arrived, the fingerprint degrades to a named **coarse** class and `CardIdentity.coarse` says
  which input was missing. A coarse fingerprint is a wider bucket, not a guess: it is the honest
  identity available from what was actually read.

Parsing is fail-closed in a specific way: a *malformed* value (wrong type, over the bound, an
unmapped status word, a SHA that is not hex, a job list that is not a list) raises `MalformedSource`
naming the field, and nothing about that run is admitted. A *missing* value that the source is
entitled to omit (no job list, no log, no steps) becomes a `CoverageNote` on the fact, which travels
into the card body as "not captured" and into the event stream as a `coverage` event. That is the
pair `platform/detections.py` emits -- coverage first, then the verdict the coverage says is judgeable
-- and it is why a truncated log changes the card's coarseness instead of changing its claim.

No credential, hostname, URL query or email survives `scrub_excerpt`, and the scrubbed text is what
gets hashed *and* what gets printed on the card, so the two can never disagree about what was safe to
show.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import datetime as dt
import re
from typing import Any
from collections.abc import Mapping, Sequence

from local_observe.inventory.validation import digest, timestamp
from .transports import MalformedSource

__all__ = ['CardIdentity', 'CoverageNote', 'DEFAULT_MAIN_BRANCHES', 'EPOCH_SENTINEL',
           'FAILING_CONCLUSIONS', 'RunFact', 'RunRoute', 'card_identity', 'error_hash',
           'event_identity', 'is_failure', 'parse_run', 'parse_run_path', 'plane_of', 'scrub_excerpt']

#: Gitea's Actions task statuses. `waiting`/`blocked`/`queued` are the starved-runner class the card
#: calls `ci.run.stuck`; anything outside this set is a version drift and is refused, not guessed at.
RUN_STATUSES = frozenset({'queued', 'in_progress', 'waiting', 'blocked', 'completed', 'unknown'})
#: The conclusions Gitea has ever sent for a completed task, including the ones it sends by mistake.
#: The empty string means "still running" and is only legal with a non-terminal `status`.
CONCLUSIONS = frozenset({'', 'success', 'failure', 'cancelled', 'skipped', 'neutral', 'action_required',
                         'timed_out', 'unknown'})
#: Conclusions that mean "this build did not produce a green result". `action_required` is included:
#: a job parked on a manual approval gate has failed nothing, but the pipeline is not green either,
#: and a card that says "action required" is more useful than silence.
FAILING_CONCLUSIONS = frozenset({'failure', 'cancelled', 'timed_out', 'action_required'})
#: A run whose status is not `completed` has no conclusion to read yet.
TERMINAL_STATUS = 'completed'

MAIN = 'main'
PULL = 'pull'
BRANCH = 'branch'
#: Gitea's own end-to-end event words, as the real API spells them. Nothing else routes a run.
PULL_EVENTS = frozenset({'pull_request', 'merge_group'})
#: Which branches count as main-red when no operator set names them. `master` is here because a
#: repository created before 2021 usually has it as its default branch, and main-red is the one class
#: this pipeline must never under-report.
DEFAULT_MAIN_BRANCHES = ('main', 'master')

UNKNOWN = 'unknown'
NONE = 'none'

#: Gitea answers an *unfinished* run or job with `completed_at` equal to the Unix epoch (and Go's zero
#: time for a never-populated column). Neither is a moment in 1970: recorded as a timestamp it turns
#: every queued run into a 56-year-old outage, so both mean "unavailable" here and carry a note.
EPOCH_SENTINEL = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
SENTINEL_SLACK_SECONDS = 300
MAX_NAME_CHARS = 200
MAX_TEXT_CHARS = 500
MAX_JOBS = 100
MAX_STEPS = 50
MAX_SHA_CHARS = 40
EXCERPT_HASH_CHARS = 12
FINGERPRINT_CHARS = 16
EVENT_KEY_CHARS = 32

_SHA = re.compile(r'^[0-9a-f]{7,40}$')
# The real Actions API answers a run object with `path` (`ci.yml@refs/heads/main`,
# `ci.yml@refs/pull/42/head`) and *without* `workflow_id`, `name`, `workflow_name` or `head_branch`.
# So `path` is the only workflow identity and the only ref there is, and its grammar is closed: a
# bounded `.yml`/`.yaml` file with no `..` and no empty segment, then `@`, then a recognised ref.
_WORKFLOW_FILE = re.compile(r'^(?!.*\.\.)(?!.*//)[A-Za-z0-9.][A-Za-z0-9._/-]{0,79}\.ya?ml$')
_HEADS_REF = re.compile(r'^refs/heads/([A-Za-z0-9][A-Za-z0-9._/-]{0,119})$')
_PULL_REF = re.compile(r'^refs/(?:pull|merge)/([1-9][0-9]{0,9})/(?:head|merge)$')
_TAGS_REF = re.compile(r'^refs/tags/([A-Za-z0-9][A-Za-z0-9._/-]{0,119})$')
_ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
_HEX_RUN = re.compile(r'\b[0-9a-f]{7,40}\b')
_ABS_PATH = re.compile(r"(?:/[A-Za-z0-9._@+-]+){2,}")
_WINDOWS_PATH = re.compile(r'[A-Za-z]:[\\/](?:[A-Za-z0-9._@+-]+[\\/]?)+')
_TIMESTAMP = re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b')
_DURATION = re.compile(r'\b\d+(?:\.\d+)?\s?(?:ms|s|sec|secs|seconds?|min|mins|m|h|hours?)\b')
_NUMBER = re.compile(r'\b\d+\b')
# `key: value` / `key=value` where the key reads like a credential, and any bearer-ish scheme. Both
# are refused *before* hashing: an excerpt that carried a token would otherwise be committed to the
# board in a card body, which is the one place a redaction miss is public.
_SECRET_PAIR = re.compile(r'(?i)\b(authorization|api[-_]?key|access[-_]?token|secret|token|password|'
                          r'passwd|credential|cookie|session[-_]?id)\b\s*[:=]\s*\S+')
_SECRET_SCHEME = re.compile(r'(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/-]{6,}={0,2}')
_WHITESPACE = re.compile(r'\s+')

#: The annotation/error fields a Gitea task may use for its failure text. Checked in order; the first
#: non-empty one is the excerpt, so the hash is a function of the fields, not of their arrival order.
EXCERPT_FIELDS = ('error_excerpt', 'failure_reason', 'message', 'conclusion_details')


@dataclass(frozen=True)
class CoverageNote:
    """One honest gap: what this pipeline could not read, and where it came from."""
    reason: str
    detail: str = NONE

    def line(self) -> str:
        return self.reason if self.detail in (NONE, '') else f'{self.reason} ({self.detail})'


@dataclass(frozen=True)
class StepFact:
    name: str
    status: str
    conclusion: str

    @property
    def failing(self) -> bool:
        return self.conclusion in FAILING_CONCLUSIONS


@dataclass(frozen=True)
class JobFact:
    """One job of a run: its identity, its verdict, the step pointed at, and its three stamps.

    Gitea gives a *job* the `created_at` / `started_at` / `completed_at` triple that the run object has
    no `created_at` for: `created_at` is when the job was queued, `started_at` when a runner picked it
    up. That gap is the only queue timing this package may speak about, and it is used only as a
    justified, coverage-noted fallback (see `parse_run`), never as a run timestamp it did not have.
    """
    job_id: int
    name: str
    status: str
    conclusion: str
    steps: tuple[StepFact, ...] = ()
    failure_reason: str | None = None
    created_at: dt.datetime | None = None
    started_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None

    @property
    def failing(self) -> bool:
        return self.conclusion in FAILING_CONCLUSIONS

    def first_failing_step(self) -> str:
        for step in self.steps:
            if step.failing:
                return step.name
        return NONE


@dataclass(frozen=True)
class RunFact:
    """One CI run, read and validated: the unit of both identities and of the delivery journal.

    `coverage` is never empty-by-accident: every gap in the read (no job list, no log, a truncated
    tail, a run still queued) is a note here, and the card body and the coverage events are generated
    from it. `excerpt` is the *scrubbed* text, so what this package files is byte-identical to what it
    hashed.
    """
    repository: str
    run_id: int
    head_sha: str
    head_branch: str
    event: str
    status: str
    conclusion: str
    workflow_id: str
    workflow_name: str
    jobs: tuple[JobFact, ...] = ()
    excerpt: str | None = None
    coverage: tuple[CoverageNote, ...] = ()
    plane: str = BRANCH
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None
    started_waiting_at: dt.datetime | None = None
    started_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None
    pr_number: int | None = None
    workflow_source: str = 'fields'

    @property
    def is_failure(self) -> bool:
        return is_failure(self.status, self.conclusion)

    @property
    def observed_at(self) -> dt.datetime | None:
        """The newest instant this run actually carried, in the order the reader trusts it.

        `updated_at` and `created_at` are what a GitHub-shaped API offers and what Gitea leaves absent;
        `completed_at` and `started_at` are what it really sends. Falling through to `None` is honest:
        callers then use their own clock rather than inventing a run timestamp.
        """
        for moment in (self.updated_at, self.completed_at, self.started_at, self.created_at):
            if moment is not None:
                return moment
        return None

    def failure_class(self) -> str:
        """The word that names what happened, for a card title and an event summary."""
        if self.status != TERMINAL_STATUS:
            return 'stuck'
        return self.conclusion or UNKNOWN

    def coverage_reasons(self) -> tuple[str, ...]:
        return tuple(note.reason for note in self.coverage)

    def first_failing_job(self) -> str:
        for job in self.jobs:
            if job.failing:
                return job.name
        return NONE

    def first_failing_step(self) -> str:
        for job in self.jobs:
            if job.failing:
                step = job.first_failing_step()
                if step != NONE:
                    return step
        return NONE


@dataclass(frozen=True)
class CardIdentity:
    """The fingerprint that groups failures onto one card, plus what had to be dropped to compute it."""
    fingerprint: str
    signature: str
    coarse: bool
    reasons: tuple[str, ...] = field(default=())

    @property
    def identity_class(self) -> str:
        return 'coarse' if self.coarse else 'precise'


@dataclass(frozen=True)
class RunRoute:
    """What a run's `path` proves: which workflow file ran, on which ref, and the plane that implies.

    `branch` is `None` for a pull ref (a PR head is not a branch this pipeline may route on) and for a
    tag; `plane` is `''` when the path carried no ref, which sends routing back to `plane_of` rather
    than defaulting to a guess.
    """
    workflow: str
    ref: str
    branch: str | None
    pr_number: int | None
    plane: str


def parse_run_path(path: Any) -> RunRoute | None:
    """Split `<workflow file>@<git ref>` into workflow identity and routing ref.

    Returns `None` when the field is absent or empty (a forge that still carries `name`/`workflow_id`);
    raises `MalformedSource` when a *present* path is unreadable -- an `@`-bearing string naming no
    bounded workflow file, a ref prefix outside the three Gitea writes, or a non-string. Refusing is
    the point: bucketing every unrecognised path under one workflow name merges unrelated pipelines
    into a single event identity, which is the defect this function replaces.
    """
    if path is None:
        return None
    if not isinstance(path, str):
        raise MalformedSource('run path must be a string')
    text = path.strip()
    if not text:
        return None
    if text.count('@') > 1:
        raise MalformedSource('run path carries more than one ref separator')
    file_part, _, ref_part = (segment.strip() for segment in text.partition('@'))
    if not _WORKFLOW_FILE.match(file_part):
        raise MalformedSource('run path does not name a bounded workflow file')
    workflow = file_part.removeprefix('.gitea/workflows/')
    if not ref_part:
        return RunRoute(workflow=workflow, ref='', branch=None, pr_number=None, plane='')
    pull = _PULL_REF.match(ref_part)
    if pull:
        return RunRoute(workflow=workflow, ref=ref_part, branch=None, pr_number=int(pull.group(1)),
                        plane=PULL)
    heads = _HEADS_REF.match(ref_part)
    if heads:
        return RunRoute(workflow=workflow, ref=ref_part, branch=heads.group(1), pr_number=None,
                        plane='')
    if _TAGS_REF.match(ref_part):
        return RunRoute(workflow=workflow, ref=ref_part, branch=None, pr_number=None, plane=BRANCH)
    raise MalformedSource('run path carries an unrecognised git ref')


def plane_of(branch: str, event: str, *,
             main_branches: Sequence[str] = DEFAULT_MAIN_BRANCHES) -> str:
    """`main` / `pull` / `branch` -- the routing axis, computed from two validated strings.

    The branch wins over the event: a `workflow_dispatch` against main is main-red (someone
    re-ran the thing that is broken), and a `pull_request` from a branch called main is not. That
    ordering is the whole reason this function exists rather than a lookup on `event`. It is the
    fallback route: when the run carries a `path`, `parse_run` uses the ref inside it, because the real
    API sends `head_branch` as null and this function would then answer `branch` for every main build.
    """
    if branch in set(main_branches):
        return MAIN
    if event.startswith('pull_request') or event == 'merge_group':
        return PULL
    return BRANCH


def is_failure(status: str, conclusion: str) -> bool:
    """A completed run with a failing conclusion, or an unfinished run that is not progressing."""
    if status == TERMINAL_STATUS:
        return conclusion in FAILING_CONCLUSIONS
    return False


def _text(value: Any, field_name: str, *, default: str = UNKNOWN, maximum: int = MAX_NAME_CHARS) -> str:
    """A bounded non-empty string, or the field refusal -- never a coerced repr of somebody's object."""
    if value is None:
        return default
    if not isinstance(value, str):
        raise MalformedSource(f'{field_name} must be a string')
    text = value.strip()
    if not text:
        return default
    if len(text) > maximum or any(ord(char) < 0x20 or ord(char) == 0x7f for char in text):
        raise MalformedSource(f'{field_name} is unbounded or carries control characters')
    return text


def _identifier(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise MalformedSource(f'{field_name} must be a positive integer')
    return value


def _moment(value: Any, field_name: str) -> dt.datetime | None:
    """A real instant, or `None` for absent *and* for Gitea's not-finished-yet sentinel. Never a zero."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise MalformedSource(f'{field_name} must be a timestamp string')
    if not value.strip() or value.startswith('0001-01-01'):
        return None
    try:
        moment = timestamp(value)
    except Exception:
        raise MalformedSource(f'{field_name} is not a timezone-aware ISO timestamp') from None
    if moment <= EPOCH_SENTINEL + dt.timedelta(seconds=SENTINEL_SLACK_SECONDS):
        return None
    return moment


def _epoch_sentinel(value: Any) -> bool:
    """True when a field Gitea fills with a placeholder holds that placeholder, not a moment."""
    if not isinstance(value, str) or not value.strip():
        return False
    if value.strip().startswith('0001-01-01'):
        return True
    try:
        moment = timestamp(value)
    except Exception:
        return False
    return moment <= EPOCH_SENTINEL + dt.timedelta(seconds=SENTINEL_SLACK_SECONDS)


def _reading(payload: Mapping[str, Any], field_name: str,
             notes: list[CoverageNote]) -> dt.datetime | None:
    """One timestamp with its placeholder named out loud, so 'unavailable' is a recorded state."""
    moment = _moment(payload.get(field_name), field_name)
    if moment is None and _epoch_sentinel(payload.get(field_name)):
        notes.append(CoverageNote('timestamp-unavailable', f'{field_name} is the epoch placeholder'))
    return moment


def _workflow_token(value: Any, field_name: str, maximum: int) -> str:
    """A workflow identifier as text: a bounded string, or a positive integer id rendered as text."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return ''
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return _text(str(value), field_name, default='', maximum=maximum)
    return _text(value, field_name, default='', maximum=maximum)


def _sha(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MalformedSource('head_sha is required to attribute a run')
    sha = value.strip().lower()
    if not _SHA.match(sha):
        raise MalformedSource('head_sha is not a hexadecimal commit id')
    return sha[-MAX_SHA_CHARS:]


def _steps(job: Mapping[str, Any], position: int) -> tuple[StepFact, ...]:
    raw = job.get('steps')
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_STEPS:
        raise MalformedSource(f'job {position} steps are not a bounded array')
    steps: list[StepFact] = []
    for index, step in enumerate(raw):
        if not isinstance(step, Mapping):
            raise MalformedSource(f'job {position} step {index} is not an object')
        conclusion = _text(step.get('conclusion'), f'job {position} step {index} conclusion',
                           default='', maximum=32)
        if conclusion not in CONCLUSIONS:
            raise MalformedSource(f'job {position} step {index} carries an unknown conclusion')
        status = _text(step.get('status'), f'job {position} step {index} status')
        steps.append(StepFact(name=_text(step.get('name'), f'job {position} step {index} name'),
                              status=status[:40] if status else UNKNOWN, conclusion=conclusion))
    return tuple(steps)


def _jobs(payload: Mapping[str, Any]) -> tuple[JobFact, ...]:
    """The nested job array of one run, parsed strictly. Absent is a coverage gap, not an empty list.

    Callers pass the run dict; a run object that carries `workflow_jobs`/`jobs` inline (some
    deployments nest the array under the run, others hand back `{"jobs": [...]}` from the jobs
    endpoint) is read here so the two shapes produce the same fact.
    """
    raw: Any = None
    for key in ('workflow_jobs', 'jobs'):
        candidate = payload.get(key)
        if isinstance(candidate, Mapping) and isinstance(candidate.get('jobs'), list):
            candidate = candidate['jobs']
        if candidate is not None and not isinstance(candidate, list):
            raise MalformedSource(f'{key} is not an array of job objects')
        if isinstance(candidate, list):
            raw = candidate
            break
    if raw is None:
        return ()
    if len(raw) > MAX_JOBS:
        raise MalformedSource('job array exceeds the bound')
    jobs: list[JobFact] = []
    for index, job in enumerate(raw):
        if not isinstance(job, Mapping):
            raise MalformedSource(f'job {index} is not an object')
        conclusion = _text(job.get('conclusion'), f'job {index} conclusion', default='', maximum=32)
        if conclusion not in CONCLUSIONS:
            raise MalformedSource(f'job {index} carries an unknown conclusion')
        status = _text(job.get('status'), f'job {index} status', maximum=32)
        if status not in RUN_STATUSES and status != UNKNOWN:
            raise MalformedSource(f'job {index} carries an unknown status')
        reason = job.get('failure_reason')
        jobs.append(JobFact(job_id=_identifier(job.get('id'), f'job {index} id'),
                            name=_text(job.get('name'), f'job {index} name'),
                            status=status, conclusion=conclusion, steps=_steps(job, index),
                            failure_reason=None if reason is None else _text(
                                reason, f'job {index} failure_reason', maximum=MAX_TEXT_CHARS),
                            created_at=_moment(job.get('created_at'), f'job {index} created_at'),
                            started_at=_moment(job.get('started_at'), f'job {index} started_at'),
                            completed_at=_moment(job.get('completed_at'), f'job {index} completed_at')))
    return tuple(jobs)


def parse_run(repository: str, payload: Any, *, jobs: Sequence[Mapping[str, Any]] = (),
              log: str | None = None, coverage: Sequence[CoverageNote] = (),
              main_branches: Sequence[str] = DEFAULT_MAIN_BRANCHES) -> RunFact:
    """Build one validated `RunFact` from a run object plus its job list and log tail.

    Args:
        repository: The already-validated `owner/repo` this run belongs to.
        payload: One run object as the Actions endpoint returned it.
        jobs: Job objects from `/runs/{id}/jobs`, if that read succeeded. Empty means "unknown", and
            is recorded as coverage rather than as "the build had no jobs".
        log: The raw log text (scrubbed here, before hashing and before filing).
        coverage: Gaps the caller already knows about (a failed job read, a truncated tail).
        main_branches: Which branch names count as the main plane; operator configuration, never
            inferred from the payload.

    Raises:
        MalformedSource: Any field this function cannot read without inventing something. The caller
            records the refusal against that run and moves on -- never a partial fact.
    """
    if not isinstance(payload, Mapping):
        raise MalformedSource('run payload is not an object')
    status = _text(payload.get('status'), 'run status', maximum=32)
    if status not in RUN_STATUSES:
        raise MalformedSource('run carries an unknown status')
    conclusion = _text(payload.get('conclusion'), 'run conclusion', default='', maximum=32)
    if conclusion not in CONCLUSIONS:
        raise MalformedSource('run carries an unknown conclusion')
    if status == TERMINAL_STATUS and not conclusion:
        raise MalformedSource('a completed run must carry a conclusion')
    notes = list(coverage)
    branch = _text(payload.get('head_branch'), 'head_branch')
    event = _text(payload.get('event'), 'run event')
    route = parse_run_path(payload.get('path'))
    workflow_id = _workflow_token(payload.get('workflow_id'), 'workflow_id', 64)
    workflow_name = _workflow_token(payload.get('name') or payload.get('workflow_name'),
                                    'workflow name', MAX_NAME_CHARS)
    source = 'fields'
    if route is not None:
        source = 'path'
        workflow_id = workflow_id or route.workflow
        workflow_name = workflow_name or route.workflow
    if not (workflow_id or workflow_name):
        raise MalformedSource('workflow identity is unavailable: no path, name or workflow_id')
    plane, pr_number = _route(route, branch, event, main_branches, notes)
    if route is not None and route.branch is not None:
        branch = route.branch
    parsed_jobs = (tuple(_job_from_mapping(job, index) for index, job in enumerate(jobs))
                   if jobs else _jobs(payload))
    if not parsed_jobs:
        notes.append(CoverageNote('job-list-absent', 'no job objects reached this parser'))
    excerpt: str | None = None
    if isinstance(log, str) and log.strip():
        excerpt = scrub_excerpt(log)
        if not excerpt:
            notes.append(CoverageNote('job-log-unreadable', 'every character was scrubbed'))
    elif not any(note.reason == 'job-logs-not-wired' for note in notes):
        notes.append(CoverageNote('job-log-absent'))
    created_at = _reading(payload, 'created_at', notes)
    updated_at = _reading(payload, 'updated_at', notes)
    started_at = _reading(payload, 'started_at', notes)
    completed_at = _reading(payload, 'completed_at', notes)
    waiting = _moment(payload.get('run_started_at') or payload.get('queue_time'), 'run_started_at')
    if waiting is None:
        queued = sorted(job.created_at for job in parsed_jobs if job.created_at is not None)
        if queued:
            waiting = queued[0]
            notes.append(CoverageNote('queue-time-from-job-created-at',
                                      'no run-level queue stamp; earliest job queue stamp used'))
    return RunFact(repository=repository,
                   run_id=_identifier(payload.get('id'), 'run id'),
                   head_sha=_sha(payload.get('head_sha')),
                   head_branch=branch, event=event,
                   status=status, conclusion=conclusion,
                   workflow_id=workflow_id, workflow_name=workflow_name,
                   jobs=parsed_jobs, excerpt=excerpt, coverage=tuple(notes),
                   plane=plane, created_at=created_at, updated_at=updated_at,
                   started_waiting_at=waiting, started_at=started_at, completed_at=completed_at,
                   pr_number=pr_number, workflow_source=source)


def _route(route: RunRoute | None, branch: str, event: str,
           main_branches: Sequence[str],
           notes: list[CoverageNote]) -> tuple[str, int | None]:
    """Decide the plane, letting the ref in `path` outrank `head_branch` and `event`.

    The live API sends neither `head_branch` nor a workflow name, so a run pushed to main arrives as
    `path=ci.yml@refs/heads/main` with `head_branch` null: routing on the branch string alone reads
    every main build as an ordinary branch and main-red stops reporting. A pull ref is `pull` even when
    `head_branch` says `main` (a PR whose source branch is called main, or a PR base called main --
    neither is ever read here) and even when the event word is `push`. Disagreement between the three
    is recorded as coverage, never averaged into a compromise plane.
    """
    mains = set(main_branches)
    if route is None or not route.ref:
        if route is not None:
            notes.append(CoverageNote('run-path-without-ref', 'routed on head_branch and event'))
        return plane_of(branch, event, main_branches=main_branches), None
    pull_event = event in PULL_EVENTS or event.startswith('pull_request')
    if route.plane == PULL:
        if branch in mains or not pull_event:
            notes.append(CoverageNote('run-ref-outranks-branch-evidence',
                                      f'ref {route.ref} against head_branch {branch} / event {event}'))
        return PULL, route.pr_number
    if route.branch is not None:
        if branch not in (UNKNOWN, route.branch):
            raise MalformedSource('run path and head_branch name different branches')
        if pull_event:
            notes.append(CoverageNote('run-ref-outranks-event-evidence',
                                      f'ref {route.ref} against event {event}'))
        return MAIN if route.branch in mains else BRANCH, None
    return route.plane, None


def _job_from_mapping(job: Any, index: int) -> JobFact:
    if not isinstance(job, Mapping):
        raise MalformedSource(f'job {index} is not an object')
    return _jobs({'jobs': [job]})[0]


def scrub_excerpt(text: str) -> str:
    """Reduce a log tail to the shape of the error: no paths, hosts, secrets, timings or numbers.

    Order matters. Secrets go first (a hex-valued credential would otherwise be eaten by the hex rule
    and leave the *word* `token` behind as a fingerprint input), then absolute paths, then hex runs
    (commit ids), then timestamps/durations/numbers, then whitespace. Each rule replaces with a
    fixed placeholder so two runs of the same failure scrub to the same string and one fingerprint
    covers both.
    """
    result = _ANSI.sub('', text)
    result = _SECRET_PAIR.sub('<credential>', result)
    result = _SECRET_SCHEME.sub('<credential>', result)
    result = _WINDOWS_PATH.sub('<path>', result)
    result = _ABS_PATH.sub('<path>', result)
    result = _TIMESTAMP.sub('<time>', result)
    result = _DURATION.sub('<duration>', result)
    result = _HEX_RUN.sub('<sha>', result)
    result = _NUMBER.sub('<n>', result)
    result = _WHITESPACE.sub(' ', result).strip()
    return result[-MAX_TEXT_CHARS:]


def error_hash(fact: RunFact) -> str | None:
    """The 12-hex signature of the failure text, or `None` when there is none to hash.

    Sources in priority order: the scrubbed log tail, then a job's own `failure_reason`. Both absent
    is `None`, and `card_identity` turns that into a coarse fingerprint naming the missing input --
    this function never substitutes the job name or the workflow name for evidence it did not have.
    """
    if fact.excerpt:
        return digest(['excerpt', fact.excerpt])[:EXCERPT_HASH_CHARS]
    for job in fact.jobs:
        if job.failing and job.failure_reason:
            return digest(['reason', scrub_excerpt(job.failure_reason)])[:EXCERPT_HASH_CHARS]
    return None


def event_identity(fact: RunFact) -> str:
    """The event-level key: one build, twins collapsed, re-runs collapsed, SHA included.

    The projection is `(repository, workflow, head_sha, plane-class, verdict-class, finished-or-waiting)`.
    `run_id`, `run_number` and `event` are absent on purpose: a re-run and the push+PR twin builds of one
    commit are the same fact seen more than once. `plane` enters only as a **two-valued** class (main or
    work), never as `main`/`pull`/`branch`: the routing difference between a PR build and a branch build
    must survive into the card, while a three-valued plane here would let a push and its PR twin open two
    events for one SHA -- and a plane-class split is what keeps a work-plane build from ever swallowing a
    main one.
    """
    return digest(['ci-event', fact.repository, fact.workflow_id or fact.workflow_name,
                   fact.head_sha, 'main' if fact.plane == MAIN else 'work',
                   'failed' if fact.is_failure else fact.conclusion,
                   'stuck' if fact.status != TERMINAL_STATUS else 'finished'])[:EVENT_KEY_CHARS]


def card_identity(fact: RunFact) -> CardIdentity:
    """The card-level key: one *problem*, SHA-free, with the coarse fallback named out loud."""
    reasons: list[str] = []
    step = fact.first_failing_step()
    if step == NONE:
        reasons.append('first-failing-step-absent')
    hashed = error_hash(fact)
    if hashed is None:
        reasons.append('error-excerpt-absent')
    workflow = fact.workflow_id or fact.workflow_name
    if not fact.jobs:
        reasons.append('job-list-absent')
    parts = ['ci-card', fact.repository, workflow, fact.failure_class(), fact.first_failing_job(),
             step, hashed or 'COARSE']
    signature = (f'{fact.repository} {workflow} {fact.first_failing_job()}/{step} '
                 f'{fact.failure_class()}')
    return CardIdentity(fingerprint=digest(parts)[:FINGERPRINT_CHARS],
                        signature=signature[:MAX_NAME_CHARS],
                        coarse=bool(reasons),
                        reasons=tuple(reasons) or (NONE,))

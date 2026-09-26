"""The board outlet: decide, record the intent, write, and reconcile what a crash left undecided.

Three steps, in this order, and the order is the design:

1. `plan` turns stored occurrences into **intent rows** (`deliveries`) and touches nothing remote. A
   decision that is not durable can be lost; a decision that is durable can be re-attempted by a
   different process, so filing survives a kill at any point after this line.
2. `reconcile` looks at the board and asks what already happened: is the card for this fingerprint
   already open (either this process filed it and died before the checkpoint, or something else did)?
   If so the intent is *adopted*, not repeated. This is the only answer available when a write
   succeeded and its acknowledgement was lost -- remote writes are not atomic, and no client can make
   an HTTP POST idempotent after the fact. What this package can guarantee is that the effect is
   discovered before it is duplicated, and that the gap between "we meant to" and "we know we did" is
   never silent.
3. `drain` performs the pending writes, oldest intent first, and stops on the first transport-class
   failure (`blocked`). Continuing to hammer a board that is refusing writes would turn one outage
   into a thousand attempts and would still not deliver anything.

Deduplication uses a stable audit marker: a `fingerprint: <hex16>` line
in the body, plus a `filed-by:` marker, plus a scan of open issues before filing. A recurrence on an
already-filed fingerprint is a **comment**, never a second card.

Non-atomic remote writes, stated plainly: `create_issue` can succeed on the server and time out on the
client. The recovery is the scan, and its limits are the limits of the scan -- if two copies of this
outlet run at once, or if the issue is closed between the scan and the write, or if the repository's
open-issue list is longer than the page budget (in which case the scan *refuses* rather than returning
a partial list), the guarantee is a refusal or a duplicate, never a silent wrong answer. `Pipeline`
takes an exclusive owner lock over the state file to close the first case; the second is a human
decision, and the third is the page-budget refusal above.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import datetime as dt
import re
from typing import Any
from collections.abc import Mapping, Sequence

from local_observe.log import get_logger
from .facts import CardIdentity, RunFact, card_identity
from .store import (Delivery, STATE_PENDING, CiFailureStore)
from .transports import (BoardClient, CiFailureError, MalformedSource, PaginationBudget, ScopeRefused,
                         SourceUnavailable)

log = get_logger(__name__)

__all__ = ['BoardOutlet', 'DrainReport', 'FilingPlan', 'OutletConfig', 'ReconcileReport', 'Thresholds',
           'batch_token', 'fingerprint_of_body', 'is_main_red']

#: The card convention: a bounded hex line the scan reads back, and a marker naming the filer so a
#: human can tell this outlet's cards from the auditor's. Both lines are outside any fenced block,
#: because the scan ignores fenced blocks and an excerpt must not be able to impersonate a card.
FINGERPRINT_LINE = re.compile(r'(?im)^fingerprint:\s*([0-9a-f]{16})\s*$')
OWNED_MARKER = 'filed-by: ci-failure-pipeline'
FENCE = re.compile(r'(?ms)^```.*?^\s*```\s*$')
#: A machine tag naming the exact run batch one comment carries. Its whole job is the case the scan
#: cannot see: a comment that reached the board and whose acknowledgement was lost. On restart the
#: outlet reads the comments back, finds its own tag, and adopts the delivery instead of writing the
#: same recurrence twice.
BATCH_TAG = re.compile(r'(?is)ci-batch:\s*([0-9a-f]{8})')

#: Write bounds on generated content. `MAX_BODY_CHARS` sits under the transport's own ceiling so a
#: long storm window degrades the excerpt it shows, never the filing.
MAX_BODY_CHARS = 30000
MAX_RUN_LINES = 10
MAX_TITLE_CHARS = 180


@dataclass(frozen=True)
class Thresholds:
    """When a fingerprint becomes a card: N occurrences across M distinct SHAs inside the window.

    Both counts, not either alone: three failures on one SHA is one broken commit (the worker's own
    iterate loop, which the card explicitly says must not page), and one failure on each of three SHAs
    is a flaky test that nobody should be filing cards about. The conjunction is the thing that has
    actually recurred.

    `main_red_files_immediately` is the exception that outranks the counts: a broken main is not
    batched, and this pipeline's silence about main is the failure mode the card names.
    """
    occurrences: int = 3
    distinct_shas: int = 2
    window_days: int = 7
    labels: tuple[str, ...] = ('aiops', 'audit-finding')
    main_red_files_immediately: bool = True

    def __post_init__(self) -> None:
        for name in ('occurrences', 'distinct_shas'):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1000:
                raise CiFailureError(f'Threshold {name} is out of range')
        if not 1 <= int(self.window_days) <= 7:
            raise CiFailureError('Threshold window must fit the platform window ceiling')
        if not 1 <= len(self.labels) <= 5:
            raise CiFailureError('A card needs at least one label and no more than five')
        for name in self.labels:
            if not isinstance(name, str) or not 1 <= len(name) <= 50 or not re.fullmatch(
                    r'[A-Za-z0-9][A-Za-z0-9._/-]{0,49}', name):
                raise CiFailureError('Card label names are outside the bounded character class')

    def met(self, count: int, distinct_shas: int) -> bool:
        return count >= self.occurrences and distinct_shas >= self.distinct_shas


@dataclass(frozen=True)
class OutletConfig:
    """The outlet's own knobs, all of which an operator sets and a test overrides."""
    thresholds: Thresholds = field(default_factory=Thresholds)
    file_cards: bool = True
    max_writes_per_drain: int = 20
    run_link_base: str = ''
    verification_note: str = ('Not verified live by a human: this card is generated from the Actions '
                             'API reads listed below.')

    def __post_init__(self) -> None:
        if not 1 <= int(self.max_writes_per_drain) <= 100:
            raise CiFailureError('Invalid per-drain write budget')
        if self.run_link_base and (not self.run_link_base.startswith('https://')
                                   or ' ' in self.run_link_base or '@' in self.run_link_base
                                   or len(self.run_link_base) > 200):
            raise CiFailureError('run_link_base must be an https URL without credentials')


@dataclass(frozen=True)
class FilingPlan:
    """What `plan` decided, in words a report line can carry."""
    created: tuple[str, ...] = ()
    commented: tuple[str, ...] = ()
    held: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {'planned_create': list(self.created), 'planned_comment': list(self.commented),
                'held': [{'fingerprint': item, 'reason': reason} for item, reason in self.held]}


@dataclass(frozen=True)
class ReconcileReport:
    adopted: tuple[tuple[str, int], ...] = ()
    unresolved: tuple[tuple[str, str], ...] = ()
    scanned: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {'adopted': [{'fingerprint': item, 'issue_number': number} for item, number in self.adopted],
                'unresolved': [{'fingerprint': item, 'reason': reason} for item, reason in self.unresolved],
                'scanned': self.scanned}


@dataclass(frozen=True)
class DrainReport:
    """The observable outcome of one drain: what went, what was adopted, and what is still owed."""
    delivered: tuple[str, ...] = ()
    adopted: tuple[str, ...] = ()
    blocked: tuple[tuple[str, str], ...] = ()
    superseded: tuple[tuple[str, str], ...] = ()
    error: str | None = None

    @property
    def clean(self) -> bool:
        return not self.blocked and self.error is None

    @property
    def delivered_count(self) -> int:
        return len(self.delivered) + len(self.adopted)

    def as_dict(self) -> dict[str, Any]:
        return {'delivered': list(self.delivered), 'adopted': list(self.adopted),
                'blocked': [{'id': item, 'reason': reason} for item, reason in self.blocked],
                'superseded': [{'id': item, 'reason': reason} for item, reason in self.superseded],
                'error': self.error, 'clean': self.clean}


def fingerprint_of_body(body: Any) -> str | None:
    """The fingerprint a card declares, or None. Fenced blocks are stripped before matching.

    A log excerpt is attacker-influenced text (whoever wrote the failing job controls it), and this
    function decides whether a card is *ours*. Stripping fenced regions first is what stops an excerpt
    that prints `fingerprint: 0123456789abcdef` from making the outlet adopt an unrelated issue, and
    the `OWNED_MARKER` check in `_owned_issue` is what stops any other 16-hex line doing the same.
    """
    if not isinstance(body, str) or len(body) > MAX_BODY_CHARS:
        return None
    match = FINGERPRINT_LINE.search(FENCE.sub('', body))
    return match.group(1) if match else None


def is_main_red(fact: RunFact) -> bool:
    return fact.plane == 'main' and fact.is_failure


def batch_token(run_ids: Sequence[int]) -> str:
    """The 8-hex tag for one comment's run batch: same runs in, same token out, forever."""
    from local_observe.inventory.validation import digest
    return digest(['ci-batch', sorted(int(value) for value in run_ids)])[:8]


class BoardOutlet:
    """Files and updates one card per fingerprint, through the board client and nothing else."""

    def __init__(self, store: CiFailureStore, board: BoardClient, *,
                 config: OutletConfig | None = None) -> None:
        if board is None:
            raise ScopeRefused('The outlet needs a board client')
        self.store = store
        self.board = board
        self.config = config or OutletConfig()
        self._scan_cache: dict[str, dict[str, Any]] | None = None
        self._label_cache: dict[str, int] | None = None

    # ---- content ------------------------------------------------------------

    def title_for(self, identity: CardIdentity, fact: RunFact) -> str:
        prefix = 'main red:' if is_main_red(fact) else 'ci failure:'
        return f'{prefix} {fact.repository} {fact.workflow_name or fact.workflow_id}'[:MAX_TITLE_CHARS]

    def run_link(self, fact: RunFact) -> str:
        """A run reference: a URL only when the operator configured a base, never a guessed host."""
        if self.config.run_link_base:
            return (f'{self.config.run_link_base.rstrip("/")}/{self.board.owner}/{self.board.name}'
                    f'/actions/runs/{fact.run_id}')
        return f'run {fact.run_id} in {fact.repository}'

    def body_for(self, identity: CardIdentity, fact: RunFact, stats: Any, *,
                 coverage_lines: Sequence[str] = ()) -> str:
        """The card body: signature, window numbers, run links, excerpt, and what was *not* checked."""
        threshold = self.config.thresholds
        lines = [
            f'fingerprint: {identity.fingerprint}',
            OWNED_MARKER,
            '',
            f'Signature: {identity.signature}',
            f'Identity class: {identity.identity_class}'
            + (f' (missing: {", ".join(identity.reasons)})' if identity.coarse else ''),
            '',
            '## Window',
            '',
            f'- Occurrences: {stats.count} (threshold {threshold.occurrences})',
            f'- Distinct SHAs: {stats.distinct_shas} (threshold {threshold.distinct_shas})',
            f'- First seen: {stats.first_seen.isoformat() if stats.first_seen else "unknown"}',
            f'- Last seen: {stats.last_seen.isoformat() if stats.last_seen else "unknown"}',
            f'- Planes seen: {", ".join(sorted(stats.planes)) or "unknown"}',
            f'- SHAs: {", ".join(sha[:10] for sha in stats.shas[:8]) or "none"}',
            '',
            '## Runs',
            '',
        ]
        for run_id in stats.run_ids[:MAX_RUN_LINES]:
            lines.append(f'- run {run_id} in {fact.repository}')
        if len(stats.run_ids) > MAX_RUN_LINES:
            lines.append(f'- ... {len(stats.run_ids) - MAX_RUN_LINES} more runs in the window')
        lines += ['', '## Latest run', '',
                  f'- Run: {self.run_link(fact)}',
                  f'- Branch: {fact.head_branch} ({fact.plane} plane)',
                  f'- Status/conclusion: {fact.status}/{fact.conclusion or "n/a"}',
                  f'- Jobs: {", ".join(job.name for job in fact.jobs) or "not captured"}',
                  f'- First failing step: {fact.first_failing_step()}',
                  '']
        if fact.excerpt:
            lines += ['## Log excerpt (scrubbed)', '', '```', fact.excerpt, '```', '']
        else:
            lines += ['## Log excerpt', '', 'Not captured: '
                      + ', '.join(fact.coverage_reasons()) + '.', '']
        lines += ['## Coverage gaps', '',
                  f'- Log excerpt captured: {"yes" if fact.excerpt else "no"}',
                  f'- Job list captured: {"yes" if fact.jobs else "no"}']
        for note in coverage_lines:
            lines.append(f'- {note}')
        lines += ['', '## Check before reporting', '',
                  '- Read live from the Actions API: run list, run jobs'
                  + (', job log' if fact.excerpt else ' (no log body read)'),
                  f'- Threshold applied without a model: {threshold.occurrences} occurrences across '
                  f'{threshold.distinct_shas} SHAs inside {threshold.window_days} days',
                  '- Not verified: no host inspection, no reproduction, no cause analysis by this '
                  'pipeline',
                  '- This card is a report of a recurring CI failure, not a diagnosis of it',
                  '']
        body = '\n'.join(lines)
        if len(body) > MAX_BODY_CHARS:
            body = body[:MAX_BODY_CHARS - 40] + '\n...truncated by the filing bound...\n'
        return body

    def comment_for(self, identity: CardIdentity, fact: RunFact, stats: Any, *,
                    acknowledged: int, run_ids: Sequence[int]) -> str:
        """The recurrence comment: counts and a link, because the card body already carries the rest."""
        return '\n'.join([
            f'{OWNED_MARKER} recurrence',
            f'fingerprint: {identity.fingerprint}',
            f'<!-- ci-batch: {batch_token(run_ids)} -->',
            '',
            f'- Occurrences now: {stats.count} across {stats.distinct_shas} SHA(s) in '
            f'{self.config.thresholds.window_days}d',
            f'- Runs added since this comment series began: '
            f'{max(0, len(stats.run_ids) - acknowledged)}',
            f'- Latest: {self.run_link(fact)} ({fact.head_branch}, {fact.plane} plane)',
            f'- First failing step: {fact.first_failing_step()}',
            f'- Identity class: {"coarse" if identity.coarse else "precise"}',
            '',
            'Filed once per fingerprint: this is a comment, not a second card.',
        ])[:MAX_BODY_CHARS]

    # ---- plan ---------------------------------------------------------------

    def plan(self, facts: Sequence[tuple[RunFact, CardIdentity]], *, now: dt.datetime) -> FilingPlan:
        """Turn this tick's folded occurrences into intent rows. No remote call happens here.

        Storm folding lives in this method, not in the caller: occurrences are grouped by fingerprint
        first, so fifty starved-runner runs produce one create (or one comment carrying all fifty run
        ids), never fifty of anything. The comment batch is keyed by its highest run id, so a replayed
        tick recomputes the same key and the journal -- not a variable in memory -- decides whether that
        batch has already been promised to the board.
        """
        grouped: dict[str, list[tuple[RunFact, CardIdentity]]] = {}
        for fact, identity in facts:
            grouped.setdefault(identity.fingerprint, []).append((fact, identity))
        created: list[str] = []
        commented: list[str] = []
        held: list[tuple[str, str]] = []
        for fingerprint, members in sorted(grouped.items()):
            members.sort(key=lambda pair: pair[0].run_id)
            newest_fact, _identity = members[-1]
            stats = self.store.window(fingerprint, now=now)
            if stats.count == 0:
                held.append((fingerprint, 'no-occurrences-in-window'))
                continue
            filing = self.store.filing(fingerprint)
            if filing is None:
                if not self.config.file_cards:
                    held.append((fingerprint, 'card-filing-disabled'))
                    continue
                main_red = any(is_main_red(fact) for fact, _ in members)
                if not main_red and not self.config.thresholds.met(stats.count, stats.distinct_shas):
                    held.append((fingerprint, 'below-threshold'))
                    continue
                detail = {'title': self.title_for(_identity, newest_fact),
                          'body': self.body_for(_identity, newest_fact, stats),
                          'main_red': main_red}
                delivery_id, new = self.store.plan_delivery(fingerprint=fingerprint,
                                                            repository=newest_fact.repository,
                                                            action='create', run_ids=stats.run_ids,
                                                            detail=detail, now=now)
                if new:
                    created.append(delivery_id)
                continue
            unacknowledged = [run_id for run_id in stats.run_ids
                              if run_id not in self.store.acknowledged_runs(fingerprint)]
            if not unacknowledged:
                held.append((fingerprint, 'already-acknowledged'))
                continue
            detail = {'issue_number': int(filing['issue_number']),
                      'batch': batch_token(unacknowledged),
                      'body': self.comment_for(_identity, newest_fact, stats,
                                               acknowledged=int(filing['occurrences_filed']),
                                               run_ids=unacknowledged),
                      'run_ids': sorted(unacknowledged)}
            delivery_id, new = self.store.plan_delivery(fingerprint=fingerprint,
                                                        repository=newest_fact.repository,
                                                        action='comment', run_ids=unacknowledged,
                                                        detail=detail, now=now)
            if new:
                commented.append(delivery_id)
        return FilingPlan(tuple(created), tuple(commented), tuple(held))

    # ---- scan / reconcile ---------------------------------------------------

    def _open_by_fingerprint(self, *, refresh: bool = False) -> dict[str, dict[str, Any]]:
        """`fingerprint -> open issue` from one scan, cached for the whole call sequence.

        Caching is not freshness laundering: the cache is dropped by every `drain` that writes, so a
        card this outlet just created is invisible to nothing -- and a scan that fails is not replaced
        by a stale cache, it raises and the delivery stays pending.
        """
        if self._scan_cache is not None and not refresh:
            return self._scan_cache
        found: dict[str, dict[str, Any]] = {}
        for issue in self.board.open_issues():
            fingerprint = fingerprint_of_body(issue.get('body'))
            number = issue.get('number')
            if fingerprint is None or isinstance(number, bool) or not isinstance(number, int) or number <= 0:
                continue
            if not self._owned_issue(issue):
                continue
            found.setdefault(fingerprint, {'number': number, 'title': issue.get('title')})
        self._scan_cache = found
        return found

    @staticmethod
    def _owned_issue(issue: Mapping[str, Any]) -> bool:
        body = issue.get('body')
        return isinstance(body, str) and OWNED_MARKER in FENCE.sub('', body)

    def reconcile(self, *, now: dt.datetime) -> ReconcileReport:
        """Adopt or explain every pending intent before attempting anything new.

        Called first on every run, including the very first, so a process that was killed between a
        successful `POST /issues` and its checkpoint resumes by finding its own card rather than by
        filing a second one. A scan that fails leaves every intent pending with a reason: the delivery
        state is retained, and "we could not look" is reported instead of "we have nothing to do".
        """
        pending = [delivery for delivery in self.store.pending_deliveries()
                   if delivery.state == STATE_PENDING]
        if not pending:
            return ReconcileReport()
        try:
            open_issues = self._open_by_fingerprint(refresh=True)
        except (SourceUnavailable, MalformedSource, PaginationBudget) as exc:
            for delivery in pending:
                self.store.mark_blocked(delivery.id, f'scan-unavailable:{type(exc).__name__}', now)
            log.warning('Board scan unavailable; deliveries retained',
                        extra={'pending': len(pending), 'error_class': type(exc).__name__})
            return ReconcileReport(unresolved=tuple((delivery.fingerprint, 'scan-unavailable')
                                                    for delivery in pending))
        except ScopeRefused as exc:  # a mis-wired client, not an outage: loud, and nothing is written.
            raise exc
        adopted: list[tuple[str, int]] = []
        unresolved: list[tuple[str, str]] = []
        for delivery in pending:
            if delivery.action == 'create':
                number = self._found_card(delivery, open_issues)
                if number is None:
                    unresolved.append((delivery.fingerprint, 'no-card-found'))
                    continue
                self.store.mark_adopted(delivery.id, issue_number=number, now=now)
                self.store.remember_filing(delivery.fingerprint, delivery.repository, number,
                                           str(delivery.detail.get('title') or '')[:200],
                                           occurrences_filed=len(delivery.run_ids),
                                           last_ack_run=max(delivery.run_ids), now=now)
                adopted.append((delivery.fingerprint, number))
                continue
            # A comment is only adopted when its own batch tag is on the board. A filing receipt proves
            # the card exists; it does not prove this recurrence was ever told -- adopting on the receipt
            # alone would lose the occurrence, which is the other half of the defect the card names.
            number = self._found_card(delivery, open_issues)
            if number is None:
                unresolved.append((delivery.fingerprint, 'no-card-found'))
                continue
            try:
                posted = self._batch_posted(number, str(delivery.detail.get('batch') or ''))
            except (SourceUnavailable, MalformedSource, PaginationBudget) as exc:
                self.store.mark_blocked(delivery.id, f'comment-read-unavailable:{type(exc).__name__}', now)
                unresolved.append((delivery.fingerprint, 'comment-read-unavailable'))
                continue
            if not posted:
                unresolved.append((delivery.fingerprint, 'comment-not-yet-posted'))
                continue
            self.store.mark_adopted(delivery.id, issue_number=number, now=now)
            filing = self.store.filing(delivery.fingerprint) or {}
            self.store.remember_filing(delivery.fingerprint, delivery.repository, number,
                                       str(filing.get('title') or '')[:200],
                                       occurrences_filed=int(filing.get('occurrences_filed') or 0)
                                       + len(delivery.run_ids),
                                       last_ack_run=max(delivery.run_ids), now=now)
            adopted.append((delivery.fingerprint, number))
        return ReconcileReport(adopted=tuple(adopted), unresolved=tuple(unresolved), scanned=True)

    def _found_card(self, delivery: Delivery, open_issues: Mapping[str, dict[str, Any]]) -> int | None:
        """The issue number this fingerprint is filed under: the receipt first, then the board scan."""
        filing = self.store.filing(delivery.fingerprint)
        if filing is not None:
            return int(filing['issue_number'])
        found = open_issues.get(delivery.fingerprint)
        return None if found is None else int(found['number'])

    def _batch_posted(self, issue_number: int, token: str) -> bool:
        """Whether one issue already carries the comment with this batch tag.

        The read is the only proof available: an issue's comment list is what survives a lost
        acknowledgement. A comment body whose tag matches but which does not carry this outlet's marker
        is not adopted -- somebody else writing `ci-batch:` must not be able to silence a delivery.
        """
        if not re.fullmatch(r'[0-9a-f]{8}', token or ''):
            return False
        for comment in self.board.issue_comments(issue_number):
            body = comment.get('body')
            if not isinstance(body, str) or len(body) > MAX_BODY_CHARS:
                continue
            found = BATCH_TAG.search(body)
            if found is not None and found.group(1) == token:
                return OWNED_MARKER in body
        return False

    # ---- drain --------------------------------------------------------------

    def _labels_for_create(self) -> tuple[list[int], list[str]]:
        """Label ids for the configured names, plus the names the board does not have.

        A missing label is coverage, not a reason to invent one: the card is filed with the labels that
        exist and the body says which were absent. The outlet never creates a label (that is a board
        write this scope does not hold) and never substitutes a kanban label to make a filing succeed.
        """
        if self._label_cache is None:
            self._label_cache = self.board.label_ids()
        ids, missing = [], []
        for name in self.config.thresholds.labels:
            number = self._label_cache.get(name)
            if number is None:
                missing.append(name)
            else:
                ids.append(int(number))
        return ids, missing

    def drain(self, *, now: dt.datetime) -> DrainReport:
        """Attempt the pending intents, in order, stopping at the first failure.

        Stopping is a feature: on an outage the remaining intents keep their position and their
        `attempts` counter says how many ticks the board has been refusing us for. Every failure here
        calls `mark_blocked`, which keeps the row pending -- an observable `blocked` delivery, never a
        dropped one.
        """
        delivered: list[str] = []
        adopted: list[str] = []
        blocked: list[tuple[str, str]] = []
        superseded: list[tuple[str, str]] = []
        budget = self.config.max_writes_per_drain
        for delivery in self.store.pending_deliveries():
            if self._superseded(delivery):
                reason = 'filing-receipt-exists'
                self.store.supersede(delivery.id, reason, now)
                superseded.append((delivery.id, reason))
                continue
            if budget <= 0:
                blocked.append((delivery.id, 'write-budget-exhausted'))
                continue
            try:
                outcome, issue_number, reason = self._attempt(delivery, now=now)
            except (SourceUnavailable, MalformedSource, PaginationBudget) as exc:
                reason = f'{delivery.action}-failed:{type(exc).__name__}'
                self.store.mark_blocked(delivery.id, reason, now)
                blocked.append((delivery.id, reason))
                log.warning('Board write retained for retry', extra={'fingerprint': delivery.fingerprint,
                                                                    'action': delivery.action,
                                                                    'error_class': type(exc).__name__})
                continue
            except ScopeRefused as exc:
                # A scope refusal is this package asking for something it must not ask for. Retrying it
                # would be the same bug on a timer, so the run stops and the intent stays pending.
                self.store.mark_blocked(delivery.id, f'scope-refused:{type(exc).__name__}', now)
                raise
            if outcome == 'blocked':
                self.store.mark_blocked(delivery.id, reason or 'attempt-blocked', now)
                blocked.append((delivery.id, reason or 'attempt-blocked'))
                continue
            budget -= 1
            if outcome == 'delivered':
                delivered.append(delivery.id)
            elif outcome == 'adopted':
                adopted.append(delivery.id)
            if issue_number is not None:
                self._scan_cache = None
        return DrainReport(tuple(delivered), tuple(adopted), tuple(blocked), tuple(superseded))

    def _superseded(self, delivery: Delivery) -> bool:
        """A create intent whose fingerprint already has a receipt is finished, not pending.

        Reached when `plan` ran before a filing landed, or when a restart recomputed a create that a
        previous process already delivered. Silently filing again would be the duplicate the card's
        acceptance clause is about.
        """
        return delivery.action == 'create' and self.store.filing(delivery.fingerprint) is not None

    def _attempt(self, delivery: Delivery, *, now: dt.datetime) -> tuple[str, int | None, str | None]:
        """One write, with its checkpoint: `(outcome, issue_number, reason)`.

        `outcome` is `delivered`, `adopted` or `blocked`; `blocked` carries the reason and leaves the
        row pending. Transport and shape failures are *raised* (the caller owns the retry decision);
        only a refusal to proceed without a receipt -- the board never having shown the card a comment
        is meant for -- comes back as a value.
        """
        if delivery.action == 'create':
            return self._attempt_create(delivery, now=now)
        return self._attempt_comment(delivery, now=now)

    def _attempt_create(self, delivery: Delivery, *, now: dt.datetime) -> tuple[str, int | None, str | None]:
        """Scan the open cards, then file -- the audit runner's dedup order, in that order.

        The scan is not redundant with `plan`: a second process, or a card filed by hand while this one
        was deciding, is invisible to the journal. Adopting on a fingerprint match is also what makes the
        non-atomic remote write survivable: if our own `POST` landed and its answer did not, the next
        drain sees the card and closes the delivery instead of filing a copy of it.
        """
        detail = delivery.detail
        found = self._open_by_fingerprint(refresh=True).get(delivery.fingerprint)
        if found is not None:
            number = int(found['number'])
            self.store.mark_adopted(delivery.id, issue_number=number, now=now)
            self.store.remember_filing(delivery.fingerprint, delivery.repository, number,
                                       str(detail.get('title') or '')[:200],
                                       occurrences_filed=len(delivery.run_ids),
                                       last_ack_run=max(delivery.run_ids), now=now)
            return 'adopted', number, None
        label_ids, missing = self._labels_for_create()
        body = str(detail.get('body') or '')
        if missing:
            body += ('\n## Labels not applied\n\n'
                     + '\n'.join(f'- `{name}` is absent on this repository' for name in missing)
                     + '\n')
        created = self.board.create_issue(str(detail.get('title') or 'ci failure'), body,
                                          labels=label_ids)
        number = int(created['number'])
        self.store.mark_delivered(delivery.id, issue_number=number, now=now)
        self.store.remember_filing(delivery.fingerprint, delivery.repository, number,
                                   str(detail.get('title') or '')[:200],
                                   occurrences_filed=len(delivery.run_ids),
                                   last_ack_run=max(delivery.run_ids), now=now)
        return 'delivered', number, None

    def _attempt_comment(self, delivery: Delivery, *, now: dt.datetime) -> tuple[str, int | None, str | None]:
        number = self._issue_for_comment(delivery)
        if number is None:
            return 'blocked', None, 'no-filing-receipt'
        batch = str(delivery.detail.get('batch') or '')
        if self._batch_posted(number, batch):
            self.store.mark_adopted(delivery.id, issue_number=number, now=now)
            return 'adopted', number, None
        self.board.comment(number, str(delivery.detail.get('body') or ''))
        self.store.mark_delivered(delivery.id, issue_number=number, now=now)
        filing = self.store.filing(delivery.fingerprint) or {}
        self.store.remember_filing(delivery.fingerprint, delivery.repository, number,
                                   str(filing.get('title') or '')[:200],
                                   occurrences_filed=int(filing.get('occurrences_filed') or 0)
                                   + len(delivery.run_ids),
                                   last_ack_run=max(delivery.run_ids), now=now)
        return 'delivered', number, None

    def _issue_for_comment(self, delivery: Delivery) -> int | None:
        """Which issue this comment belongs on: the receipt, then a fresh scan, then nothing.

        Returning None is the honest answer when a restart lost the receipt and the card is not on the
        board -- posting a comment to an issue number we invented would attribute a recurrence to
        somebody else's work item.
        """
        if delivery.issue_number:
            return int(delivery.issue_number)
        filing = self.store.filing(delivery.fingerprint)
        if filing is not None:
            return int(filing['issue_number'])
        found = self._open_by_fingerprint().get(delivery.fingerprint)
        return None if found is None else int(found['number'])

"""The two scoped HTTP seams: a GET-only Actions reader and a separately scoped board writer.

Nothing in this module opens a socket. Both clients talk to an injected *transport* whose shape
matches `local_observe.http.JsonClient.request`, so the unit tier runs the real construction path
(the service builder in `pipeline.py` builds these exact objects) against a recording fake, and the
live acceptance run swaps in `HttpJsonTransport` with no other change.

Why two clients and not one client with a wider allowlist: the Actions read is the credential this
pipeline uses every few seconds, and it is the one a bug or an attacker reaches first. If that
credential could also open an issue, every defect in the reader became a board write. `BoardClient`
therefore owns the writes and carries its own token, and `pipeline.Pipeline` refuses the two clients
sharing one transport -- "same credential, different method filter" is not a configuration this
package can produce.

Every path a client can build is assembled from two validated parts: a repository identity matched
against a closed character class, and integer ids that `int()` had to accept. Callers never hand a
path string to either client, which is why the hostile-input tests (traversal, encoded separators,
unicode look-alikes, `..` inside a repository name) fail in the constructor or in the id validator
rather than at the transport.

Refusal classes, and what each one means downstream:

* `ScopeRefused` -- this package asked for something it must never ask for. A bug or an attack; never
  retried, and it fails the run loudly rather than degrading.
* `MalformedSource` -- the answer arrived and is not the shape the endpoint promises. The one payload
  carrying it is refused and recorded; the walk stops rather than continuing over unread text.
* `SourceUnavailable` -- the read did not complete, or completed with an error status. That is
  *coverage* about this ingestion source; cursor, facts and pending deliveries stay exactly as they
  were.
* `PaginationBudget` -- the walk hit its page ceiling before the source said it had ended. Never
  returned as if it were a complete list: an incomplete scan that looks complete is how one failure
  turns into fifty cards.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Protocol
from collections.abc import Mapping, Sequence

from local_observe.log import get_logger

log = get_logger(__name__)

__all__ = ['ActionsSource', 'BoardClient', 'CiFailureError', 'HttpJsonTransport', 'JsonTransport',
           'LIMIT_PARAMETER', 'LogRead', 'MAX_ISSUE_BODY_CHARS', 'MAX_JOBS_PAGES', 'MAX_JOBS_PER_RUN',
           'MAX_LOG_CHARS', 'MAX_PAGES', 'MAX_TITLE_CHARS', 'MalformedSource', 'PER_PAGE_MAX',
           'PaginationBudget', 'ScopeRefused', 'SourceUnavailable', 'repository_identity']

#: Page-walk bounds. `MAX_PAGES` x `PER_PAGE_MAX` = 1,000 rows per walk: two orders of magnitude above
#: what one poll of one repository legitimately needs, and low enough that a source paging forever is
#: a refusal in seconds rather than an unbounded read.
MAX_PAGES = 20
PER_PAGE_MAX = 50

#: Gitea's list endpoints answer to **two** different page-size spellings, and the live capture proved
#: which one it obeys: `?per_page=3` returned 30 rows (its default) while `?limit=3` returned 3. Every
#: list request here therefore carries both, so the caller's bound is honoured on either spelling, and
#: a page that answers *more* rows than it was asked for is a `MalformedSource` rather than a walk that
#: quietly ends early -- a 30-row page read as "shorter than 50, so that was everything" is how a
#: failure below the first page is never ingested at all while the cursor advances past it.
LIMIT_PARAMETER = 'limit'
PER_PAGE_PARAMETER = 'per_page'

#: How many job pages one run may cost. `MAX_JOBS_PER_RUN` mirrors `facts.MAX_JOBS`, the bound the
#: parser enforces on the array it is handed; the test suite asserts the two stay equal. A run whose
#: job list is bigger than the bound is a `PaginationBudget` refusal -- coverage on that run, never a
#: truncated job list presented as the whole build.
MAX_JOBS_PAGES = 4
MAX_JOBS_PER_RUN = 100

#: Board write bounds. A title over `MAX_TITLE_CHARS` or a body over `MAX_ISSUE_BODY_CHARS` is refused
#: before the request: Gitea's own limits are in the same region, and a write it truncates silently
#: would corrupt the fingerprint line the dedup scan reads back.
MAX_TITLE_CHARS = 200
MAX_ISSUE_BODY_CHARS = 65536

#: How much of a job log this package will hold. The tail is what carries the failing assertion, so
#: the *end* is kept; anything beyond is a coverage note and a coarser card identity.
MAX_LOG_CHARS = 4096

#: `owner` and `name` each: a leading alphanumeric, then alphanumerics, dot, dash or underscore, up to
#: 64. A segment that is only dots is refused (that is `.`/`..`), and the client joins exactly these
#: two tokens into one path segment pair, so no surviving value can re-add a separator.
_REPO_SEGMENT = re.compile(r'^(?!\.+$)[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')


class CiFailureError(ValueError):
    """Base for every bounded refusal this package raises."""


class ScopeRefused(CiFailureError):
    """A method, path or write outside this client's declared scope. Never retried."""


class MalformedSource(CiFailureError):
    """The remote body was readable but is not the shape the endpoint promises."""


class SourceUnavailable(CiFailureError):
    """The read did not complete, or completed with an error status: coverage, not a verdict."""


class PaginationBudget(CiFailureError):
    """The page walk hit its ceiling before the source said it was finished."""


@dataclass(frozen=True)
class LogRead:
    """One job-log read: either text, or the coverage sentence explaining why there is none.

    `excerpt` is `None` whenever `coverage` names a reason -- the reader is not wired, the answer was
    empty, the status was an error, or the tail was cut. Callers hash `excerpt` only when present: a
    missing log is a gap in *this pipeline's* knowledge, so it changes how coarse the card identity
    has to be, and never what the card claims about the build.
    """
    excerpt: str | None
    coverage: str | None
    truncated: bool = False


class Transport(Protocol):
    """The injected request surface -- the same call `local_observe.http.JsonClient` offers."""

    def request(self, method: str, path: str, *, params: Mapping[str, Any] | None = None,
                payload: Mapping[str, Any] | None = None) -> tuple[int, Any]:
        ...


class JsonTransport:
    """Production transport over one `http.JsonClient`, with query values bounded to scalars.

    `params` become the query string here rather than at the call site, so no caller can splice text
    into a URL by hand. Only `int` and short closed-class strings are admitted -- page numbers, page
    sizes and state words -- because those are the only query values either client ever needs.
    """

    _SCALAR = re.compile(r'^[A-Za-z0-9._,-]{1,32}$')

    def __init__(self, client: Any) -> None:
        if not callable(getattr(client, 'request', None)):
            raise CiFailureError('Transport needs a JsonClient-shaped request method')
        self.client = client

    def request(self, method: str, path: str, *, params: Mapping[str, Any] | None = None,
                payload: Mapping[str, Any] | None = None) -> tuple[int, Any]:
        query = []
        for name, value in sorted((params or {}).items()):
            if not re.fullmatch(r'[a-z_]{1,16}', name):
                raise CiFailureError('Invalid query parameter name')
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise CiFailureError(f'Query parameter {name} must be a scalar')
            if isinstance(value, str) and not self._SCALAR.match(value):
                raise CiFailureError(f'Query parameter {name} carries an unapproved character')
            query.append(f'{name}={value}')
        full = path + ('?' + '&'.join(query) if query else '')
        return self.client.request(method, full, payload=payload)


#: The same class under the name a reader of `pipeline.build_service` looks for: it constructs the
#: HTTP-backed transport, and every test constructs one of the fake transports instead.
HttpJsonTransport = JsonTransport


def repository_identity(value: Any) -> tuple[str, str]:
    """Return `(owner, name)` for a validated `owner/repo`, refusing everything else."""
    if not isinstance(value, str) or value.count('/') != 1:
        raise ScopeRefused('Repository must be one owner/name pair')
    owner, _, name = value.partition('/')
    for segment in (owner, name):
        if not _REPO_SEGMENT.match(segment):
            raise ScopeRefused('Repository identity is outside the allowed character class')
    return owner, name


def _positive_id(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ScopeRefused(f'{field} must be an integer id')
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ScopeRefused(f'{field} must be an integer id') from None
    if not 0 < number < 2 ** 63 or str(number) != str(value).strip():
        raise ScopeRefused(f'{field} is outside the accepted id range')
    return number


def _rows(body: Any, keys: Sequence[str], *, what: str) -> list[dict[str, Any]]:
    """Pull the one array a page promises, refusing anything else rather than guessing.

    Gitea nests its list under a different word per endpoint (`workflow_runs`, `runs`, `jobs`, and a
    bare array for issues/labels), and some deployments wrap it as `{"total": n, "<key>": [...]}`. The
    accepted shapes are therefore *the first* key from `keys` holding a list, or a top-level list. A
    dict with none of those keys, a non-list value, or a list holding a non-object row is
    `MalformedSource`: the poller records coverage and leaves the cursor where it was.
    """
    if isinstance(body, Mapping):
        rows: Any = None
        for key in keys:
            if key in body:
                rows = body[key]
                break
        else:
            raise MalformedSource(f'{what} response carried none of the expected arrays')
    else:
        rows = body
    if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
        raise MalformedSource(f'{what} response array is malformed')
    return [dict(row) for row in rows]


def _page_params(page: int, size: int) -> dict[str, Any]:
    """One bounded list request: both page-size spellings carry the same number, `limit` included.

    Gitea's Actions endpoints read `limit` and ignore `per_page` (live capture: `limit=3` -> 3 rows,
    `per_page=3` -> 30). The `per_page` spelling is retained for compatible transports; `limit`
    enforces the observed Gitea contract on every list endpoint.
    """
    return {'page': int(page), PER_PAGE_PARAMETER: int(size), LIMIT_PARAMETER: int(size)}


def _within_page(rows: Sequence[Mapping[str, Any]], size: int, what: str) -> list[dict[str, Any]]:
    """Refuse a page that over-delivered, so no walk can mistake an ignored bound for its end."""
    if len(rows) > size:
        raise MalformedSource(f'{what} page returned {len(rows)} rows against a bound of {size}')
    return [dict(row) for row in rows]


class ActionsSource:
    """The read side of `/repos/{repo}/actions`: runs, their jobs, and (when wired) job logs.

    GET only, four path shapes only. There is no `post`/`put`/`patch`/`delete` attribute on this class,
    and `request` refuses any method other than `GET` *before* it matches the path, so the refusal does
    not depend on the order of checks. The allowlist is compiled from this client's own validated
    identity, which makes "issue write through the Actions credential" unrepresentable rather than
    merely untested: the string `/repos/acme/widgets/issues` cannot match any pattern here.
    """

    def __init__(self, transport: Transport, repository: str, *, log_reader: Any | None = None,
                 per_page: int = PER_PAGE_MAX) -> None:
        owner, name = repository_identity(repository)
        if not callable(getattr(transport, 'request', None)):
            raise CiFailureError('Actions source needs an injected transport')
        if isinstance(per_page, bool) or not 1 <= int(per_page) <= PER_PAGE_MAX:
            raise CiFailureError('Actions per_page is out of range')
        if log_reader is not None and not callable(log_reader):
            raise CiFailureError('Job-log reader must be callable or absent')
        self.transport = transport
        self.owner, self.name = owner, name
        self.repo = f'{owner}/{name}'
        self.per_page = int(per_page)
        self.log_reader = log_reader
        self._root = f'/repos/{owner}/{name}/actions'
        self._allowed = tuple(re.compile(pattern) for pattern in (
            rf'^{re.escape(self._root)}/runs$',
            rf'^{re.escape(self._root)}/runs/[0-9]{{1,20}}$',
            rf'^{re.escape(self._root)}/runs/[0-9]{{1,20}}/jobs$',
            rf'^{re.escape(self._root)}/runs/[0-9]{{1,20}}/jobs/[0-9]{{1,20}}/logs$',
        ))

    @property
    def scope(self) -> str:
        """The name this client's credential answers to in a report -- never a token value."""
        return 'gitea-actions-read'

    def _checked(self, method: str, path: str) -> None:
        if method != 'GET':
            raise ScopeRefused('The Actions source is GET-only')
        if not any(pattern.match(path) for pattern in self._allowed):
            raise ScopeRefused('Path is outside the Actions read allowlist')

    def request(self, method: str, path: str,
                params: Mapping[str, Any] | None = None) -> tuple[int, Any]:
        """One guarded GET, exposed so a caller (or an acceptance check) can prove the scope.

        This is the seam the review asked to be tested: the object that serves `/actions/runs` must
        refuse `POST /repos/{repo}/issues` as read-only, and refuse it without the transport ever being
        called. Anything other than `GET`, or any path outside the four allowlisted shapes, is
        `ScopeRefused` -- not a fallback, not a warning line in a log.
        """
        self._checked(method, path)
        return self.transport.request(method, path, params=params)

    def _get(self, path: str, params: Mapping[str, Any] | None) -> Any:
        status, body = self.request('GET', path, params)
        if not 200 <= int(status) < 300:
            raise SourceUnavailable(f'Actions read returned status {int(status)}')
        return body

    def runs(self, *, page: int = 1, per_page: int | None = None) -> list[dict[str, Any]]:
        """One page of run objects, newest-first as Gitea returns them, bounded by `limit`.

        Page *walking* belongs to the caller (`pipeline.Pipeline.poll_once` walks and commits per page,
        which is what lets a restart resume mid-history), so this client offers one page and its bounds
        and leaves "how much history may I read" to the layer that can answer it. A page shorter than
        the requested size is the source's own end-of-history signal -- valid only because the size was
        asked for in the spelling Gitea honours; a page longer than the bound is `MalformedSource`, so
        an ignored parameter cannot be read as a finished walk. A walk that runs out of budget before
        the short-page signal is a `PaginationBudget` refusal at the walk, never a short list passed
        off as complete.
        """
        size = self.per_page if per_page is None else int(per_page)
        if isinstance(per_page, bool) or isinstance(page, bool) or not 1 <= size <= PER_PAGE_MAX \
                or not 1 <= int(page) <= MAX_PAGES ** 2:
            raise CiFailureError('Invalid Actions runs page/per_page')
        rows = _rows(self._get(f'{self._root}/runs', _page_params(page, size)),
                     ('workflow_runs', 'runs'), what='Actions runs')
        return _within_page(rows, size, 'Actions runs')

    def run(self, run_id: Any) -> dict[str, Any] | None:
        """One run object by id (`/runs/{id}`), or `None` when the forge no longer holds it.

        The fourth allowlisted shape, and the only read that can answer a run the page walk has left
        behind: a run still queued when the cursor moved past it is below the cursor for good, so no
        future page of `/runs` will surface the fact that it failed. One bounded GET per run is the
        cheap answer; the caller decides *which* runs are worth asking about.

        A body naming a different run than was asked for is `ScopeRefused`, not a silent re-label: a
        cached or substituted detail page recorded under the requested id would attribute one build's
        verdict to another.
        """
        wanted = _positive_id(run_id, 'run_id')
        status, body = self.request('GET', f'{self._root}/runs/{wanted}', None)
        if int(status) == 404:
            return None
        if not 200 <= int(status) < 300:
            raise SourceUnavailable(f'Actions read returned status {int(status)}')
        answer = body
        if isinstance(body, Mapping) and isinstance(body.get('workflow_run'), Mapping):
            answer = body['workflow_run']
        if not isinstance(answer, Mapping):
            raise MalformedSource('Actions run detail is not an object')
        given = answer.get('id')
        if isinstance(given, bool) or not isinstance(given, int):
            raise MalformedSource('Actions run detail carries no integer id')
        if int(given) != wanted:
            raise ScopeRefused('Actions run detail answers a different run than was asked for')
        return dict(answer)

    def jobs(self, run_id: Any, *, per_page: int | None = None,
             max_pages: int = MAX_JOBS_PAGES) -> list[dict[str, Any]]:
        """Every job object of one run (`/runs/{id}/jobs`), paged and bounded, nested array and all.

        The jobs endpoint paginates like the runs endpoint and is read the same way: `limit` on every
        request, a short page as the only end-of-history signal, and a refusal -- never a short list --
        when the walk runs out of `max_pages` or would pass `MAX_JOBS_PER_RUN` rows. The caller turns
        either refusal into coverage on that run, which makes its card coarse rather than wrong.
        """
        size = self.per_page if per_page is None else int(per_page)
        if isinstance(per_page, bool) or isinstance(max_pages, bool) \
                or not 1 <= size <= PER_PAGE_MAX or not 1 <= int(max_pages) <= MAX_PAGES:
            raise CiFailureError('Invalid Actions jobs page/per_page')
        path = f'{self._root}/runs/{_positive_id(run_id, "run_id")}/jobs'
        collected: list[dict[str, Any]] = []
        for page in range(1, int(max_pages) + 1):
            rows = _rows(self._get(path, _page_params(page, size)), ('jobs',), what='Actions jobs')
            collected.extend(_within_page(rows, size, 'Actions jobs'))
            if len(collected) > MAX_JOBS_PER_RUN:
                raise PaginationBudget(f'Actions job walk passed the bound of {MAX_JOBS_PER_RUN}')
            if len(rows) < size:
                return collected
        raise PaginationBudget(f'Actions job walk exceeded {max_pages} pages without finishing')

    def job_log(self, run_id: Any, job_id: Any) -> LogRead:
        """The log tail for one job, or the coverage sentence explaining why there is none.

        The reader is injected because the endpoint answers `text/plain` where every other call here
        answers JSON: a deployment that has not wired one gets `coverage='job-logs-not-wired'` and a
        coarser card identity, which is the honest reading of "I do not know what the failing step
        said".
        """
        path = (f'{self._root}/runs/{_positive_id(run_id, "run_id")}/jobs/'
                f'{_positive_id(job_id, "job_id")}/logs')
        self._checked('GET', path)
        if self.log_reader is None:
            return LogRead(None, 'job-logs-not-wired')
        status, text = self.log_reader(path)
        if not 200 <= int(status) < 300:
            return LogRead(None, f'job-log-status-{int(status)}')
        if not isinstance(text, str) or not text.strip():
            return LogRead(None, 'job-log-empty')
        if len(text) > MAX_LOG_CHARS:
            return LogRead(text[-MAX_LOG_CHARS:], 'job-log-truncated', truncated=True)
        return LogRead(text, None)

    def verify_access(self) -> bool:
        """One bounded read proving the credential and repository path work, before any scan.

        Raises `CiFailureError` on any failure; the boolean exists so a caller can put the answer in a
        report instead of catching at every seam. This is the first leg of the order the acceptance
        names: verify the read, then scan the board, then write.
        """
        self.runs(page=1, per_page=1)
        return True


class BoardClient:
    """The write side of the board: open-issue scan, label lookup, issue create, comment create.

    Five endpoint shapes, exactly two of them writes. Closing an issue, editing a title or body,
    adding a label to an existing issue and deleting anything are refused -- an outlet that can close
    its own card can also close the evidence that it filed one, and an outlet that can relabel can
    move work across the kanban by accident. It is a separate object with a separate token for the
    same reason, and `Pipeline` refuses to hand it the Actions transport.
    """

    def __init__(self, transport: Transport, repository: str, *, per_page: int = PER_PAGE_MAX) -> None:
        owner, name = repository_identity(repository)
        if not callable(getattr(transport, 'request', None)):
            raise CiFailureError('Board client needs an injected transport')
        if isinstance(per_page, bool) or not 1 <= int(per_page) <= PER_PAGE_MAX:
            raise CiFailureError('Board per_page is out of range')
        self.transport = transport
        self.owner, self.name = owner, name
        self.repo = f'{owner}/{name}'
        self.per_page = int(per_page)
        self._root = f'/repos/{owner}/{name}'
        self._allowed: tuple[tuple[str, Any], ...] = (
            ('GET', re.compile(rf'^{re.escape(self._root)}/issues$')),
            ('GET', re.compile(rf'^{re.escape(self._root)}/labels$')),
            ('GET', re.compile(rf'^{re.escape(self._root)}/issues/[0-9]{{1,20}}/comments$')),
            ('POST', re.compile(rf'^{re.escape(self._root)}/issues$')),
            ('POST', re.compile(rf'^{re.escape(self._root)}/issues/[0-9]{{1,20}}/comments$')),
        )

    @property
    def scope(self) -> str:
        return 'board-read-write'

    def _checked(self, method: str, path: str) -> None:
        if not any(method == allowed and pattern.match(path) for allowed, pattern in self._allowed):
            raise ScopeRefused(f'{method} {path} is outside the board client scope')

    def allows(self, method: str, path: str) -> str:
        """Return *path* when this client may issue *method* there, else refuse.

        Public because the boundary it states has to be checkable from outside: an acceptance run can
        ask "can the board outlet close an issue?" and get a refusal naming the method and the path,
        rather than reading this file and guessing at the table.
        """
        self._checked(method, path)
        return path

    def _request(self, method: str, path: str, *, params: Mapping[str, Any] | None = None,
                 payload: Mapping[str, Any] | None = None) -> tuple[int, Any]:
        self.allows(method, path)
        status, body = self.transport.request(method, path, params=params, payload=payload)
        return int(status), body

    def open_issues(self, *, max_pages: int = MAX_PAGES, labels: Sequence[str] = ()) -> list[dict[str, Any]]:
        """Every open issue this repository can hand back, or a refusal -- never a partial list.

        The dedup rule ("scan open cards before filing one") is only as good as the scan, so an
        unfinished walk raises `PaginationBudget` and the caller keeps its pending delivery rather than
        filing a duplicate on top of a card it failed to see. Pull requests share this endpoint on
        Gitea, so `type=issues` is sent and rows carrying a non-null `pull_request` are dropped here
        as well -- a build's card must never be deduped against a PR.
        """
        if isinstance(max_pages, bool) or not 1 <= int(max_pages) <= MAX_PAGES:
            raise CiFailureError('Invalid issue page budget')
        issues: list[dict[str, Any]] = []
        for page in range(1, int(max_pages) + 1):
            params: dict[str, Any] = dict(_page_params(page, self.per_page),
                                          state='open', type='issues')
            if labels:
                params['labels'] = ','.join(sorted(set(labels)))
            status, body = self._request('GET', f'{self._root}/issues', params=params)
            if not 200 <= status < 300:
                raise SourceUnavailable(f'Issue scan returned status {status}')
            rows = _within_page(_rows(body, ('issues',), what='Issue scan'), self.per_page,
                                'Issue scan')
            issues.extend(row for row in rows if not isinstance(row.get('pull_request'), Mapping))
            if len(rows) < self.per_page:
                return issues
        raise PaginationBudget(f'Issue scan exceeded {max_pages} pages without finishing')

    def label_ids(self, *, max_pages: int = MAX_PAGES) -> dict[str, int]:
        """`name -> id` for the repository's labels; `create_issue` takes ids, not names."""
        if isinstance(max_pages, bool) or not 1 <= int(max_pages) <= MAX_PAGES:
            raise CiFailureError('Invalid label page budget')
        found: dict[str, int] = {}
        for page in range(1, int(max_pages) + 1):
            status, body = self._request('GET', f'{self._root}/labels',
                                         params=_page_params(page, self.per_page))
            if not 200 <= status < 300:
                raise SourceUnavailable(f'Label lookup returned status {status}')
            rows = _within_page(_rows(body, ('labels',), what='Label lookup'), self.per_page,
                                'Label lookup')
            for row in rows:
                name, number = row.get('name'), row.get('id')
                if not isinstance(name, str) or not 1 <= len(name) <= 64 or not isinstance(number, int) \
                        or isinstance(number, bool) or number <= 0:
                    raise MalformedSource('Label row is missing a bounded name or id')
                found[name] = number
            if len(rows) < self.per_page:
                return found
        raise PaginationBudget('Label lookup did not finish inside the page budget')

    def create_issue(self, title: str, body: str, *, labels: Sequence[int] = ()) -> dict[str, Any]:
        """File one issue and return its `number`/`html_url`. Non-2xx is `SourceUnavailable`.

        A rejection is never read as "someone else filed it" -- the only proof that a card exists is
        reading it back from the board, which is what `outlet.BoardOutlet.reconcile` does after a lost
        answer. Labels are ids (`label_ids`), because Gitea's create endpoint ignores names.
        """
        if not isinstance(title, str) or not title.strip() or len(title) > MAX_TITLE_CHARS:
            raise CiFailureError('Issue title is unbounded or empty')
        if not isinstance(body, str) or not body.strip() or len(body) > MAX_ISSUE_BODY_CHARS:
            raise CiFailureError('Issue body is unbounded or empty')
        if not 0 <= len(labels) <= 10:
            raise CiFailureError('Too many labels on one filing')
        ids = [_positive_id(item, 'label id') for item in labels]
        status, response = self._request('POST', f'{self._root}/issues',
                                         payload={'title': title, 'body': body, 'labels': ids})
        if not 200 <= status < 300 or not isinstance(response, Mapping):
            raise SourceUnavailable(f'Issue create returned status {status}')
        number = response.get('number')
        if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
            raise SourceUnavailable('Issue create returned no usable issue number')
        url = response.get('html_url')
        return {'number': number, 'html_url': url if isinstance(url, str) else ''}

    def comment(self, issue_number: Any, body: str) -> dict[str, Any]:
        """Add one comment to an existing issue. See `create_issue` on what a failure means."""
        number = _positive_id(issue_number, 'issue_number')
        if not isinstance(body, str) or not body.strip() or len(body) > MAX_ISSUE_BODY_CHARS:
            raise CiFailureError('Comment body is unbounded or empty')
        status, response = self._request('POST', f'{self._root}/issues/{number}/comments',
                                         payload={'body': body})
        if not 200 <= status < 300:
            raise SourceUnavailable(f'Comment write returned status {status}')
        return {'number': number,
                'response': response if isinstance(response, Mapping) else None}

    def issue_comments(self, issue_number: Any, *, max_pages: int = MAX_PAGES) -> list[dict[str, Any]]:
        """The comments already on one issue -- the read that adopts a write whose answer was lost."""
        number = _positive_id(issue_number, 'issue_number')
        if isinstance(max_pages, bool) or not 1 <= int(max_pages) <= MAX_PAGES:
            raise CiFailureError('Invalid comment page budget')
        path = f'{self._root}/issues/{number}/comments'
        comments: list[dict[str, Any]] = []
        for page in range(1, int(max_pages) + 1):
            status, body = self._request('GET', path, params=_page_params(page, self.per_page))
            if not 200 <= status < 300:
                raise SourceUnavailable(f'Comment read returned status {status}')
            rows = _within_page(_rows(body, ('comments',), what='Comment read'), self.per_page,
                                'Comment read')
            comments.extend(rows)
            if len(rows) < self.per_page:
                return comments
        raise PaginationBudget('Comment walk did not finish inside the page budget')

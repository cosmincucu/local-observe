"""The operator's entry point: one poll, or one independent liveness judgement.

Two commands, one process each, and the split is the point. `--once` is the poller: it reads, records,
delivers and checks in. `--check-heartbeat` is the monitor: it opens the same file read-only in
behaviour (it writes nothing, ever) and answers whether the poller checked in recently. Run it from its
own scheduler entry — a unit timer next to the service, or a Healthchecks-style witness — because a
liveness check that lives inside the process being watched cannot observe that the process stopped. A
poller that is SIGKILLed sweeps no heartbeats.

Three outlets, and exactly one of them is required. The Actions read is the one configuration this
process cannot run without; the **board** and the **platform** are each opt-in, and the two are
independent — `--once` with neither is a complete, useful run: it reads, records the facts, builds the
canonical events, and reports them as `platform_admission: not-configured` with nothing sent. Board
writes need *both* a board URL and `--file-cards` (or `LO_CI_FILE_CARDS=on`); asking to file cards with
no board is a refusal, not a silent no-op, because "I asked for cards and got none" must never be a
configuration that looks like it worked. The platform outlet needs a URL and a producer credential, and
when it is wired a red workflow becomes an incident in `platform/state.py` rather than an issue.

Nothing here prints or logs a credential. Tokens arrive through `local_observe.credentials` (a mounted
file whose path is in the environment, preferred over an environment value), no URL ever carries a query
string with a secret, and the emitted JSON carries counts, states and rule names only.
"""
from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path
import sqlite3
import sys
from typing import Any
from collections.abc import Mapping

from local_observe.log import get_logger
from .adapter import PlatformAdmission
from .pipeline import PipelineConfig, TickReport, build_service, environment_config
from .platform_client import PlatformIntake
from .store import CiFailureStore
from .transports import (CiFailureError, JobLogClient, JsonTransport, ScopeRefused, SourceUnavailable)

log = get_logger(__name__)

__all__ = ['main', 'build_parser', 'EXIT_OK', 'EXIT_LAPSED', 'EXIT_UNAVAILABLE', 'EXIT_REFUSED']

EXIT_OK = 0
EXIT_LAPSED = 2
EXIT_UNAVAILABLE = 3
EXIT_REFUSED = 4

#: "the caller handed me no opinion about the platform transport", which is a different question from
#: "the caller handed me `None`, meaning this run has no platform". Collapsing the two would let an
#: injected offline seam be overridden by an environment variable.
_NO_SEAM = object()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='ci-failures', description='Bounded CI failure ingestion.')
    parser.add_argument('--repository', default=None,
                        help='owner/name on the forge (else LO_CI_REPOSITORY)')
    parser.add_argument('--state', default=None,
                        help='state database file (else LO_CI_STATE_DIR/ci-failures.sqlite3)')
    parser.add_argument('--actions-url', default=None,
                        help='HTTPS API base for the Actions read (else LO_CI_ACTIONS_URL)')
    parser.add_argument('--board-url', default=None,
                        help='HTTPS API base for the board (else LO_CI_BOARD_URL); without it nothing '
                             'is filed and --file-cards is refused')
    parser.add_argument('--platform-url', default=None,
                        help='HTTPS base of the platform intake API (else LO_CI_PLATFORM_URL); without '
                             'it events are built, reported unsent, and never admitted')
    parser.add_argument('--once', action='store_true', help='run exactly one poll and exit')
    parser.add_argument('--check-heartbeat', action='store_true',
                        help='judge the last check-in and exit non-zero when it is overdue')
    parser.add_argument('--status', action='store_true', help='print the store status report and exit')
    parser.add_argument('--file-cards', action='store_true',
                        help='allow board writes during --once (off by default, needs --board-url)')
    parser.add_argument('--deadline-seconds', type=int, default=None,
                        help='heartbeat deadline for --check-heartbeat (else LO_CI_HEARTBEAT_DEADLINE_SECONDS)')
    parser.add_argument('--allow-http', action='store_true',
                        help='permit a loopback http:// API base for development only')
    parser.add_argument('--read-only-logs', action='store_true',
                        help='do not attempt job-log reads even if an endpoint is configured')
    return parser


def _moment() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _config(args: argparse.Namespace, environ: Mapping[str, str]) -> tuple[PipelineConfig, Path]:
    repository = args.repository or environ.get('LO_CI_REPOSITORY') or ''
    config, implied = environment_config(environ, repository=repository)
    state = Path(args.state) if args.state else implied
    deadline = args.deadline_seconds or config.heartbeat_deadline_seconds
    return (PipelineConfig(repository=config.repository, main_branches=config.main_branches,
                           stuck_after_seconds=config.stuck_after_seconds,
                           heartbeat_deadline_seconds=deadline, max_pages=config.max_pages,
                           per_page=config.per_page,
                           file_cards=bool(config.file_cards or args.file_cards),
                           thresholds=config.thresholds, run_link_base=config.run_link_base,
                           seed_cursor=config.seed_cursor), state)


def _base_url(value: str | None, *, environ: Mapping[str, str], variable: str,
              allow_http: bool, api_prefix: str = '/api/v1') -> str:
    """One validated HTTPS API base, completed with the API prefix the service under it really serves.

    `api_prefix` is what separates the two kinds of base an operator can name. The forge serves under
    `/api/v1` and this package builds paths like `/repos/{owner}/{repo}/actions/runs` beneath it, so a
    base of `https://forge.example.invalid` is completed for those two. The platform serves
    `/v1/events` off its own root, and completing it would ask for `/api/v1/v1/events` -- a 404 that
    reads exactly like a broken credential. The refusal rules are the same either way: HTTPS unless the
    caller said development-only, and no space, no `@`, no query, because a URL is where an operator
    might otherwise put a token.
    """
    base = value or environ.get(variable) or ''
    if not base:
        raise CiFailureError(f'{variable} (or the matching --flag) is not configured')
    if not base.startswith('https://') and not (allow_http and base.startswith('http://')):
        raise CiFailureError(f'{variable} must be an HTTPS base URL')
    if ' ' in base or '@' in base or '?' in base:
        raise CiFailureError(f'{variable} must carry no credentials or query')
    if not api_prefix:
        return base.rstrip('/')
    return base.rstrip('/') + api_prefix if not base.endswith(api_prefix) else base


def main(argv: list[str] | None = None, *, environ: Mapping[str, str] | None = None,
         transports: tuple[Any, ...] | None = None, log_reader: Any | None = None) -> int:
    """Run one CLI invocation. `transports` is the documented offline seam for tests.

    Args:
        argv: Argument list (defaults to `sys.argv[1:]`).
        environ: Environment mapping; defaults to the process environment. Credentials are read from
            it through `local_observe.credentials`, which prefers a mounted file over a value.
        transports: `(actions, board)` or `(actions, board, platform)` to inject instead of building
            HTTP clients. Either of the last two may be `None`, and `None` is a supported production
            shape rather than a degraded one: no board means no outlet and no card, no platform means
            events are built and reported unsent. Supplying them is what lets the unit tier construct
            the real service graph with no socket.
        log_reader: Job-log reader for the fine-grained card fingerprint. When absent and the transport
            graph was built here, `transports.JobLogClient` becomes the default on the Actions base and
            credential; `--read-only-logs` leaves the reader absent whatever else was passed.

    Returns:
        `EXIT_OK`, or `EXIT_LAPSED` / `EXIT_UNAVAILABLE` / `EXIT_REFUSED` for the three failure classes
        the operator needs to tell apart. Never a traceback, and never a credential in the output. A
        `--once` tick exits `EXIT_UNAVAILABLE` when *any* receipt came back refused, including a poll
        where some other event was admitted: a half-delivered verdict is still a verdict owed, and a
        monitor that reads only the exit code must not be told the tick was clean. An outlet with no
        platform wired is not a refusal -- it exits `EXIT_OK` and reports `not-configured`.

        A state file this process cannot use is a refusal (`EXIT_REFUSED`) and not a crash, on every path
        including `--status` and `--check-heartbeat`: the SQLite errors for a read-only directory, a full
        filesystem, a corrupt page or a file another process is writing (`sqlite3.OperationalError`,
        `sqlite3.DatabaseError`) are none of the classes the rest of this module raises, and a timer unit
        that saw a Python traceback learned neither the exit code nor the reason.
    """
    import os

    arguments = build_parser().parse_args(argv)
    environment = dict(os.environ if environ is None else environ)
    if [arguments.once, arguments.check_heartbeat, arguments.status].count(True) != 1:
        print('exactly one of --once, --check-heartbeat, --status is required', file=sys.stderr)
        return EXIT_REFUSED
    try:
        config, state = _config(arguments, environment)
        if arguments.status:
            with CiFailureStore(state) as store:
                print(_dump(store.status(now=_moment(),
                                         deadline_seconds=config.heartbeat_deadline_seconds)))
            return EXIT_OK
        if arguments.check_heartbeat:
            verdict = _check(state, config)
            print(_dump(verdict))
            return EXIT_LAPSED if verdict['lapsed'] else EXIT_OK
        if transports is None:
            actions_transport, board_transport, admission, reader = _wiring(arguments, environment,
                                                                          config)
        else:
            actions_transport, board_transport, admission, reader = _injected(arguments, environment,
                                                                             transports)
        service = build_service(config=config, state_path=state, actions_transport=actions_transport,
                                board_transport=board_transport, admission=admission,
                                log_reader=None if arguments.read_only_logs else (log_reader or reader))
    except ScopeRefused as exc:
        print(f'refused: {exc}', file=sys.stderr)
        return EXIT_REFUSED
    except (CiFailureError, OSError, ValueError, sqlite3.Error) as exc:
        # `sqlite3.Error` is in the net because the state file is opened for write on every one of these
        # paths, and "the directory is read-only" / "another process holds the file" arrive as SQLite
        # classes that are not any of the ones this package raises. They mean the same thing to an
        # operator as a `StoreError` does -- this process cannot use the state it was pointed at -- and
        # exit 4 with one line is the answer; a traceback is not. A `StoreError` is already a
        # `CiFailureError`, so nothing about this source's own refusals changed.
        print(f'refused: {exc}', file=sys.stderr)
        return EXIT_REFUSED
    try:
        report: TickReport = service.pipeline.poll_once(now=_moment())
    except ScopeRefused as exc:
        print(f'refused: {exc}', file=sys.stderr)
        return EXIT_REFUSED
    except SourceUnavailable as exc:
        print(f'unavailable: {exc}', file=sys.stderr)
        return EXIT_UNAVAILABLE
    except (CiFailureError, OSError, ValueError, sqlite3.Error) as exc:
        # The same net the wiring block above throws, and for the same reason: `poll_once` can fail on a
        # state row it cannot decode (`StoreError`), on a fact it cannot attribute (`CiFailureError`), or
        # on the state file itself giving out mid-tick (a locked or unreadable database), and any of those
        # arriving as a traceback would leave an operator reading a stack instead of an exit code.
        # `StoreError` is a `CiFailureError` and a `ValueError`; the two classes above are listed first
        # because their exit code is the one that says "the endpoint did not answer".
        print(f'refused: {exc}', file=sys.stderr)
        return EXIT_REFUSED
    finally:
        service.close()
    print(_dump(report.as_dict()))
    if report.error:
        return EXIT_UNAVAILABLE
    if report.refused_receipts:
        # Any receipt that came back a refusal leaves that verdict owed, and the tick that could not send
        # it is not a tick that succeeded -- even when the others went through. A poll whose events were
        # half admitted used to exit 0 while `platform_admission: mixed` said otherwise in the JSON, and
        # a job that only reads the exit status would have called it a good run.
        return EXIT_UNAVAILABLE
    return EXIT_OK


def _check(state: Path, config: PipelineConfig) -> dict[str, Any]:
    """The monitor path: judge the gap, record it if it is open, and report.

    It records the *lapse row* and nothing else -- never a heartbeat, never a delivery. So the order
    that matters is guaranteed from either side: if this process runs before the poller comes back, the
    outage is already on the books and the poller's own recovery records the same id (a no-op); if the
    poller comes back first, its `record_success` judges the gap against the old timestamp before
    moving it. Either way a returning process cannot erase the lapse it came back from.
    """
    if not state.exists():
        return {'state': 'cold-start', 'lapsed': True, 'last_success_at': None,
                'age_seconds': None, 'deadline_seconds': config.heartbeat_deadline_seconds,
                'outcome': None, 'reason': 'no state file'}
    store = CiFailureStore(state)
    try:
        verdict, lapse = store.judge_lapse(now=_moment(),
                                           deadline_seconds=config.heartbeat_deadline_seconds)
        reported = verdict.as_dict()
        reported['lapse_recorded'] = lapse is not None
        reported['lapse'] = lapse
        return reported
    finally:
        store.close()


def _wiring(arguments: argparse.Namespace, environ: Mapping[str, str],
            config: PipelineConfig) -> tuple[Any, Any, PlatformAdmission | None, Any]:
    """Build the transport graph a deployment named: Actions required, board and platform each opt-in.

    The Actions read is the one thing that cannot be absent -- without it there is no source, so a
    missing `LO_CI_ACTIONS_URL` still refuses the run. Everything past that line is optional in both
    directions, and each option costs only what it buys:

    * **board** (`LO_CI_BOARD_URL`): the outlet, and the only thing that can open an issue. No URL means
      `build_service` gets `board_transport=None`, and the service comes back with `outlet=None` -- no
      scan, no plan, no write, and the report says so rather than printing an empty card list.
    * **`--file-cards` with no board**: a refusal. The switch is a request to write, and a run that
      quietly wrote nothing because nothing was addressable is how an incident review discovers the
      cards were never there.
    * **platform** (`LO_CI_PLATFORM_URL`): posts the poll's verdicts to the platform as canonical events,
      one per incident key rather than one per run. Absent, the events are still built and counted, and
      reported `not-configured`.
    * **job logs**: on by default, because the log tail is what makes a card's fingerprint specific;
      `--read-only-logs` is the switch that keeps the run metadata-only.
    """
    actions_base = _base_url(arguments.actions_url, environ=environ, variable='LO_CI_ACTIONS_URL',
                             allow_http=arguments.allow_http)
    actions_transport = _http_transport(actions_base, 'LO_CI_ACTIONS', environ,
                                        allow_http=arguments.allow_http)
    board_url = arguments.board_url or environ.get('LO_CI_BOARD_URL')
    board_transport = None
    if board_url:
        board_transport = _http_transport(_base_url(board_url, environ=environ,
                                                   variable='LO_CI_BOARD_URL',
                                                   allow_http=arguments.allow_http),
                                         'LO_CI_BOARD', environ, allow_http=arguments.allow_http)
    elif config.file_cards:
        raise CiFailureError('board filing needs a board: pass --board-url (or set LO_CI_BOARD_URL), '
                             'or leave --file-cards off')
    reader = None
    if not arguments.read_only_logs:
        reader = _log_reader(actions_base, 'LO_CI_ACTIONS', environ, allow_http=arguments.allow_http)
    return (actions_transport, board_transport,
            _platform_admission(arguments, environ), reader)


def _injected(arguments: argparse.Namespace, environ: Mapping[str, str],
              transports: tuple[Any, ...]) -> tuple[Any, Any, PlatformAdmission | None, None]:
    """Split the documented offline seam: `(actions)`, `(actions, board)` or `(actions, board, platform)`.

    A `None` in the board slot is how a test says "this deployment has no board", which is the shape
    production runs in when nobody has turned card filing on; a `None` in the platform slot says the
    events are built and not sent. Handing over only the first two entries leaves the platform to the
    configuration, exactly as a live run resolves it -- and a URL that is not a URL is refused the same
    way offline and live. A run whose seam names all three slots never builds an HTTP client, so no
    socket can appear because a variable happened to be set.
    """
    rows = tuple(transports)
    if not 1 <= len(rows) <= 3:
        raise CiFailureError('transports is (actions[, board[, platform]]) with None for an outlet '
                             'this run has no business writing to')
    seam = rows[2] if len(rows) > 2 else _NO_SEAM
    return (rows[0], rows[1] if len(rows) > 1 else None,
            _platform_admission(arguments, environ, transport=seam), None)


def _platform_admission(arguments: argparse.Namespace, environ: Mapping[str, str], *,
                        transport: Any = _NO_SEAM) -> PlatformAdmission | None:
    """Resolve the platform outlet: a URL, an injected transport, or neither.

    With neither, the answer is `None` and the pipeline falls back to `PlatformAdmission()`: every event
    comes back `not-configured`, nothing is sent, and the report says so. That is the behaviour this CLI
    had before the platform was an option, and it is what a deployment that has not decided yet gets.

    The credential scope is `LO_CI_PLATFORM` like every other outlet here: a mounted token file named by
    `LO_CI_PLATFORM_TOKEN_FILE` is preferred over `LO_CI_PLATFORM_TOKEN`, and neither value is ever
    printed. The header scheme is the platform's own (`Bearer`, which `platform/api.py` compares in
    constant time), not the forge's `token`.

    A transport handed over by the offline seam decides the question, including when it is `None`: a
    caller that said "this run has no platform transport" must not end up with a live HTTP client built
    from an environment variable that happened to be set. The URL is still validated in that case, so a
    malformed platform base is refused identically offline and live.
    """
    url = arguments.platform_url or environ.get('LO_CI_PLATFORM_URL')
    base = None
    if url:
        base = _base_url(url, environ=environ, variable='LO_CI_PLATFORM_URL',
                         allow_http=arguments.allow_http, api_prefix='')
    if transport is _NO_SEAM:
        if base is None:
            return None
        transport = _http_transport(base, 'LO_CI_PLATFORM', environ,
                                    allow_http=arguments.allow_http, scheme='Bearer', error_body=True)
    if transport is None:
        return None
    return PlatformAdmission(PlatformIntake(transport).admit)


def _http_transport(base: str, prefix: str, environ: Mapping[str, str], *, allow_http: bool,
                    scheme: str = 'token', error_body: bool = False) -> JsonTransport:
    """Build the production transport for one credential scope, from a mounted token file.

    `scheme` is the word in front of the token in the `Authorization` header, and it is not a
    preference: the forge accepts `token`, and the platform compares `Bearer <token>` byte for byte.
    Getting it backwards does not crash anything, it produces a 401 that reads as "the credential is
    wrong" while the credential sits there perfectly valid.

    `error_body` says whether this scope's endpoint explains itself. It is set for the platform and left
    off for the forge, and the difference is what each endpoint actually answers: `platform/api.py`
    refuses with a stable code in a JSON object (`{"error": "id_conflict", "detail": "..."}`) that
    `platform_client._error_code` is written to read -- and cannot read while the transport throws the
    body away, which left every intake refusal reporting no more than "status 400". Gitea's reads are
    turned into this package's own coverage sentences by `transports.ActionsSource` and never look at a
    body, so asking for one there would buy a bounded read for nothing and change what a caller that has
    to stay byte-compatible receives.
    """
    from local_observe.http import JsonClient

    return JsonTransport(JsonClient(base, _credential(prefix, environ), scheme=scheme,
                                   allow_http=allow_http, error_body=error_body))


def _log_reader(base: str, prefix: str, environ: Mapping[str, str], *,
                allow_http: bool) -> JobLogClient:
    """The default job-log reader: the Actions base and the Actions credential, and no new scope.

    The log lives behind the same API the poller already reads, so a credential that can list a run's
    jobs can read one of those jobs' logs; asking for a third token here would buy nothing and add one
    more secret to rotate. The path handed to the reader is built by `ActionsSource.job_log` from a job
    id out of the jobs endpoint -- not from a container name, whose number is the runner's task id.

    A refusal here refuses the *whole run*, so the message names the variables that caused it: the log
    client bounds its token more tightly than the JSON client does (see `transports.JobLogClient`), so a
    token the run transport accepted can be one this reader will not carry. `--read-only-logs` is the way
    out, and it costs only the job-log half of a card fingerprint.
    """
    try:
        return JobLogClient(base, _credential(prefix, environ), allow_http=allow_http)
    except CiFailureError as exc:
        raise CiFailureError(f'{prefix}_TOKEN_FILE / {prefix}_TOKEN is not usable for the job-log read '
                             f'({exc}); pass --read-only-logs to run without job logs') from None


def _credential(prefix: str, environ: Mapping[str, str]) -> str:
    """One scope's token, or a refusal naming the variables -- never a value, never a traceback."""
    from local_observe.credentials import read_credential

    try:
        return read_credential(prefix + '_TOKEN', environ=environ)
    except KeyError:
        raise CiFailureError(f'{prefix}_TOKEN_FILE (a mounted token file) or {prefix}_TOKEN must be '
                             f'configured before this run can reach that endpoint') from None


def _dump(payload: Mapping[str, Any]) -> str:
    import json

    return json.dumps(dict(payload), sort_keys=True, default=str)


if __name__ == '__main__':  # pragma: no cover
    raise SystemExit(main())

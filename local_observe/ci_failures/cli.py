"""The operator's entry point: one poll, or one independent liveness judgement.

Two commands, one process each, and the split is the point. `--once` is the poller: it reads, records,
delivers and checks in. `--check-heartbeat` is the monitor: it opens the same file read-only in
behaviour (it writes nothing, ever) and answers whether the poller checked in recently. Run it from its
own scheduler entry — a unit timer next to the service, or a Healthchecks-style witness — because a
liveness check that lives inside the process being watched cannot observe that the process stopped. A
poller that is SIGKILLed sweeps no heartbeats.

Nothing here prints or logs a credential. The token arrives through `local_observe.credentials`
(a mounted file whose path is in the environment, preferred over an environment value), the URL never
carries a query string with a secret, and the emitted JSON carries counts, states and rule names only.
"""
from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path
import sys
from typing import Any
from collections.abc import Mapping

from local_observe.log import get_logger
from .pipeline import PipelineConfig, TickReport, build_service, environment_config
from .store import CiFailureStore
from .transports import CiFailureError, JsonTransport, ScopeRefused, SourceUnavailable

log = get_logger(__name__)

__all__ = ['main', 'build_parser', 'EXIT_OK', 'EXIT_LAPSED', 'EXIT_UNAVAILABLE', 'EXIT_REFUSED']

EXIT_OK = 0
EXIT_LAPSED = 2
EXIT_UNAVAILABLE = 3
EXIT_REFUSED = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='ci-failures', description='Bounded CI failure ingestion.')
    parser.add_argument('--repository', default=None,
                        help='owner/name on the forge (else LO_CI_REPOSITORY)')
    parser.add_argument('--state', default=None,
                        help='state database file (else LO_CI_STATE_DIR/ci-failures.sqlite3)')
    parser.add_argument('--actions-url', default=None,
                        help='HTTPS API base for the Actions read (else LO_CI_ACTIONS_URL)')
    parser.add_argument('--board-url', default=None,
                        help='HTTPS API base for the board (else LO_CI_BOARD_URL)')
    parser.add_argument('--once', action='store_true', help='run exactly one poll and exit')
    parser.add_argument('--check-heartbeat', action='store_true',
                        help='judge the last check-in and exit non-zero when it is overdue')
    parser.add_argument('--status', action='store_true', help='print the store status report and exit')
    parser.add_argument('--file-cards', action='store_true',
                        help='allow board writes during --once (off by default)')
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
              allow_http: bool) -> str:
    base = value or environ.get(variable) or ''
    if not base:
        raise CiFailureError(f'{variable} (or the matching --flag) is not configured')
    if not base.startswith('https://') and not (allow_http and base.startswith('http://')):
        raise CiFailureError(f'{variable} must be an HTTPS base URL')
    if ' ' in base or '@' in base or '?' in base:
        raise CiFailureError(f'{variable} must carry no credentials or query')
    return base.rstrip('/') + '/api/v1' if not base.endswith('/api/v1') else base


def main(argv: list[str] | None = None, *, environ: Mapping[str, str] | None = None,
         transports: tuple[Any, Any] | None = None, log_reader: Any | None = None) -> int:
    """Run one CLI invocation. `transports` is the documented offline seam for tests.

    Args:
        argv: Argument list (defaults to `sys.argv[1:]`).
        environ: Environment mapping; defaults to the process environment. Credentials are read from
            it through `local_observe.credentials`, which prefers a mounted file over a value.
        transports: `(actions_transport, board_transport)` to inject instead of building HTTP clients.
            Supplying them is what lets the unit tier construct the real service graph with no socket.
        log_reader: Optional job-log reader for the fine-grained card fingerprint.

    Returns:
        `EXIT_OK`, or `EXIT_LAPSED` / `EXIT_UNAVAILABLE` / `EXIT_REFUSED` for the three failure classes
        the operator needs to tell apart. Never a traceback, and never a credential in the output.
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
            actions_base = _base_url(arguments.actions_url, environ=environment,
                                     variable='LO_CI_ACTIONS_URL', allow_http=arguments.allow_http)
            board_base = _base_url(arguments.board_url, environ=environment, variable='LO_CI_BOARD_URL',
                                   allow_http=arguments.allow_http)
            pair = (_http_transport(actions_base, 'LO_CI_ACTIONS', environment,
                                    allow_http=arguments.allow_http),
                    _http_transport(board_base, 'LO_CI_BOARD', environment,
                                    allow_http=arguments.allow_http))
        else:
            pair = transports
        service = build_service(config=config, state_path=state, actions_transport=pair[0],
                                board_transport=pair[1],
                                log_reader=None if arguments.read_only_logs else log_reader)
    except ScopeRefused as exc:
        print(f'refused: {exc}', file=sys.stderr)
        return EXIT_REFUSED
    except (CiFailureError, OSError, ValueError) as exc:
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
    finally:
        service.close()
    print(_dump(report.as_dict()))
    if report.error:
        return EXIT_UNAVAILABLE
    if report.receipts and report.platform_admission == 'refused':
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


def _http_transport(base: str, prefix: str, environ: Mapping[str, str], *,
                    allow_http: bool) -> JsonTransport:
    """Build the production transport for one credential scope, from a mounted token file."""
    from local_observe.credentials import read_credential
    from local_observe.http import JsonClient

    token = read_credential(prefix + '_TOKEN', environ=environ)
    return JsonTransport(JsonClient(base, token, scheme='token', allow_http=allow_http))


def _dump(payload: Mapping[str, Any]) -> str:
    import json

    return json.dumps(dict(payload), sort_keys=True, default=str)


if __name__ == '__main__':  # pragma: no cover
    raise SystemExit(main())

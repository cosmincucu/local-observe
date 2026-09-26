"""Trusted local operator CLI; remote roles are handled by platform.api.

Every subcommand here is one round of one producer, or one read of the platform's own file. `slo` and
`forecast` are the one-shot form of producers that also loop, and they follow the rule that form already
sets (`drift`, `pathcheck`, `conditions`): the same `tick`, the same configuration and cursor variables
as the worker, and the store in front of the operator instead of `POST /v1/events`. `escalate` and `rca`
change the world by filing and by recording, never by sending.
"""
import argparse
import json
import os
from collections.abc import Mapping
from pathlib import Path
import sqlite3
from typing import Any

from local_observe.forecast import timetothreshold
from local_observe.http import JsonClient
from local_observe.inventory.validation import read_document, timestamp
from local_observe.log import get_logger
from local_observe.slo import alerts as slo_alerts
from . import configdrift, conditions, escalation, pathcheck, rca, verification_cli, verification_follower
from .detections import evaluate
from .notification_safety import NotificationPolicy, RecordingSink
from .notifications import deliver_one
from .state import VERSION, Actor, Store, clock

log = get_logger(__name__)

# The three delivery modes `NotificationPolicy` accepts, spelled once here so the flag cannot offer a
# mode the policy would refuse.
NOTIFICATION_MODES = ('off', 'recording', 'live')
# The variable the platform API already reads; the CLI reads the same one so one operator setting
# moves both entry points.
MODE_ENVIRONMENT = 'LO_NOTIFICATION_MODE'
# What `notify` does when neither the flag nor the environment says otherwise: record, never send.
DEFAULT_MODE = 'recording'


def notification_mode(requested: str | None) -> str:
    """Return how `notify` may deliver: the flag, then $LO_NOTIFICATION_MODE, then recording.

    Nothing here invents `live`. The product rule (security manifests) is that no infrastructure path sends to a
    human channel unless the operator said so, so `live` is reachable only when this flag or that
    variable names it. An unrecognised value is a refusal rather than a fallback: a half-typed mode
    in the environment must not quietly land on the one mode that sends.

    A variable that is present and blank is refused, not read as unset (ledger notification and state leftovers, from
    the test tooling
    review): `LO_NOTIFICATION_MODE=` in a generated environment file says "the operator wrote this
    line", and answering it with the default would make that line mean recording on one entry point
    while the API refused to boot on it. Absent is the only thing that means recording here.
    """
    if requested is not None:
        text = requested.strip()
        if not text:
            raise ValueError('--mode names no notification mode')
    elif MODE_ENVIRONMENT in os.environ:
        text = os.environ[MODE_ENVIRONMENT].strip()
        if not text:
            raise ValueError(f'{MODE_ENVIRONMENT} is set but blank; name one of '
                             f'{", ".join(NOTIFICATION_MODES)} or unset the variable')
    else:
        text = ''
    mode = text or DEFAULT_MODE
    if mode not in NOTIFICATION_MODES:
        raise ValueError(f'Notification mode must be one of {", ".join(NOTIFICATION_MODES)}')
    return mode


def check_channel(args: argparse.Namespace, mode: str) -> None:
    """Refuse a live run that has no route to send on, before it is given a client or a mode.

    Split out of `sender` because `main` needs this decision *before* the startup gate writes
    anything: a live run with no url or token file must not end up recording `live` as this
    database's delivery mode. `off` and `recording` never reach this refusal — `sender` answers them
    with a local sink and opens no credential.
    """
    if mode == 'live' and (not args.url or args.token_file is None):
        raise ValueError('live notification mode needs both --url and --token-file')


def store_reader(environment: Mapping[str, str] | None = None) -> Any:
    """Build the store read facade from the three variables the Sigma component already sets.

    `local_observe/store/backends/clickhouse.py::store_from_environment` is the only way in: store facade fixed
    one read surface and one set of bounds, so a condition producer that opened its own HTTP client would
    be a second thing to audit. The variables are named in the refusal because a half-configured round
    must say which one is missing rather than raise a bare `KeyError` from three layers down.
    """
    values = os.environ if environment is None else environment
    wanted = ('LO_CLICKHOUSE_URL', 'LO_CLICKHOUSE_USER', 'LO_CLICKHOUSE_PASSWORD_FILE')
    missing = [name for name in wanted if not values.get(name)]
    if missing:
        raise ValueError('conditions needs ' + ', '.join(missing)
                         + ' to read series; no second query transport exists in this product')
    from local_observe.store.backends.clickhouse import store_from_environment
    return store_from_environment(values)


def require_cursor_parent(cursor: Path) -> None:
    """Refuse a cursor whose directory does not exist, before anything has been read or judged.

    The parent is the operator's to create (the rule `anomaly_cursor` states for its own cursor: a
    producer that mkdirs its own state directory can create it in the wrong place and then believe it).
    What this check does **not** do is the absolute-path/no-symlink policy `anomaly_cursor` enforces —
    these two cursors are counters and not delivery guarantees, and the difference is reported rather than
    silently claimed.
    """
    parent = Path(cursor).parent
    if not parent.is_dir():
        raise ValueError(f'Cursor path {parent} does not exist; create it before the first round')


def one_cursor(named: Path | str | None, *fallbacks: str | None) -> Path:
    """The one cursor file a producer may resume from, chosen in a stated order or refused.

    Order is the flag, then each fallback in the order given (a configuration document's own key, then
    the environment variable its looping worker reads). The rule this serves is the one
    `DEPENDENCIES.md` states for a channel reachable two ways: **one producer has one cursor**, because
    two files holding "what this producer owes" means one round can re-judge a window the other already
    delivered — and a re-judged window is a different event, not a duplicate the platform can fold.
    Reading the worker's variable when the flag is absent is what keeps `lo-platform slo` and
    `python -m local_observe.slo` pointed at the same state by default; passing a *different* path on the
    command line is an operator choosing a scratch cursor for one round, which is why it is allowed and
    why the order is spoken out loud here rather than left to whichever read came first.
    """
    for candidate in (named, *fallbacks):
        if candidate:
            return Path(candidate)
    raise ValueError('no cursor path: pass --cursor or name one where the looping worker reads it')


def slo_round(store: Store, args: argparse.Namespace) -> dict[str, Any]:
    """One round of the SLO producer — every configured objective judged, and filed into this store.

    The same producer `python -m local_observe.slo` loops, reached one way instead of two: the same
    document (`--config`, else `$LO_SLO_CONFIG`), the same `alerts.tick`, the same cursor and the same
    refusals. The difference is the exit. This command files into the database in front of the operator,
    so no producer token and no `POST /v1/events` are involved, and each event is intaken under the
    source the objective document names — which is why `--source`/`$LO_SLO_SOURCE` is required: intake
    refuses an event whose source differs from the actor's identity.

    Absent configuration is off and not an error, in the shape `rca` and `conditions` already use: the
    package's own `producer_config()` logs the one INFO line naming `$LO_SLO_CONFIG` and answers `None`,
    so this command writes no sentence of its own about being switched off.
    """
    if args.config is not None:
        source = args.source or (os.environ.get(slo_alerts.SOURCE_ENVIRONMENT) or '').strip()
        if not source:
            raise ValueError(f'slo needs a producer identity: pass --source or set '
                             f'{slo_alerts.SOURCE_ENVIRONMENT}')
        config = slo_alerts.load_config(args.config, source=source)
    else:
        config = slo_alerts.producer_config()
        if config is None:
            # `producer_config` has already logged the one INFO line naming the variable; a second
            # sentence here would make "off" two lines wide depending on which entry point asked.
            return {'status': 'off', 'configured': False}
    cursor = one_cursor(args.cursor, os.environ.get(slo_alerts.CURSOR_ENVIRONMENT))
    if args.index is None:
        raise ValueError('slo --index is required with a configuration')
    require_cursor_parent(cursor)
    now = clock(args.now)
    state = slo_alerts.cursor_document(cursor, config)
    filed: list[dict[str, Any]] = []

    def deliver_slo(item: dict[str, Any]) -> None:
        # correlation followups: a CLI round groups exactly like an HTTP intake, because the alternative was two entry
        # points with two different answers about what one incident is. The callback is built per event
        # — it carries this event's producer identity and the round's one instant (`now`, the same value
        # `intake` gets, so one event carries one timestamp across its event, incident, member and audit
        # rows) — and `args.index` is the only graph it knows. Every producer command below does the
        # same thing, and since correlation followups 2 so does `lo-platform intake --index`; plain `intake` is the
        # one call
        # site that still groups nothing, because no inventory index was named for it.
        producer = Actor(item['source'], 'producer')
        filed.append(store.intake(item, producer, now=now,
                                  admission=store.grouping_admission(args.index, producer, now=now)))

    summary = slo_alerts.tick(args.index, config, cursor, store_reader(), deliver_slo, now=now,
                              state=state)
    return {'status': summary['result'], 'objectives': summary['objectives'],
            'events': summary['events'], 'refusals': summary['refusals'],
            'insufficient': summary['insufficient'], 'truncated': summary['truncated'],
            'intake': filed}


def forecast_round(store: Store, args: argparse.Namespace) -> dict[str, Any]:
    """One round of the forecast producer — every configured series projected, and filed here.

    `python -m local_observe.forecast`'s own per-round path is `__main__.round_once`, which is
    `conditions.load_cursor` plus `conditions.tick`; this is the same two calls with the store instead of
    the HTTP door in front of them, so the driver that decides *what* a round files stays alert conditions's in both
    entry points and one page bound is not restated twice. No `--source` is asked for: unlike an SLO
    document, a forecast rule names its own source and intake files each event under that identity.

    Absent configuration is off, with the package's INFO line naming `$LO_FORECAST_CONFIG` as the only
    sentence said about it.
    """
    config = timetothreshold.load_config(args.config) if args.config is not None \
        else timetothreshold.producer_config()
    if config is None:
        # As above: `producer_config` owns the off line, and it names `$LO_FORECAST_CONFIG`.
        return {'status': 'off', 'configured': False}
    cursor = one_cursor(args.cursor, config.get('cursor'),
                        os.environ.get(timetothreshold.CURSOR_ENVIRONMENT))
    if args.index is None:
        raise ValueError('forecast --index is required with a configuration')
    require_cursor_parent(cursor)
    now = clock(args.now)
    state = conditions.load_cursor(cursor, config)
    filed: list[dict[str, Any]] = []

    def deliver_forecast(item: dict[str, Any]) -> None:
        # Grouped the way `slo_round` groups: same instant, same per-event identity, same declared graph.
        producer = Actor(item['source'], 'producer')
        filed.append(store.intake(item, producer, now=now,
                                  admission=store.grouping_admission(args.index, producer, now=now)))

    summary = conditions.tick(args.index, config, cursor, store_reader(), deliver_forecast, now=now,
                              state=state)
    return {'status': summary['result'], 'rules': summary['rules'], 'events': summary['events'],
            'refusals': summary['refusals'], 'truncated': summary['truncated'], 'intake': filed}


def sender(args: argparse.Namespace, mode: str) -> JsonClient | RecordingSink:
    """Return the client `notify` may use: a network one only in live mode, a local sink otherwise.

    Recording and off never read the channel credential or construct a network client (the mode
    contract in this package's README), so the token file stays closed in those modes. `deliver_one`
    routes non-live rows to a sink on its own; passing a sink here too means a mis-routed row still
    cannot reach a channel.

    One client, one channel: that is the CLI's whole channel story, and it stays coherent because the
    store this command opens carries exactly one policy (`--database`, no channels document), so
    `reserve_route` can only ever route to that policy's channel and the claim's `channel` always names
    it. A deployment with several channels delivers through the serving process, which builds a client
    per channel; giving this command one URL and letting it send rows booked against a different label
    would be the mismatch `DEPENDENCIES.md` calls a channel reachable two ways.
    """
    if mode != 'live':
        return RecordingSink()
    check_channel(args, mode)
    return JsonClient(args.url, args.token_file.read_text().strip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    # `--database` is only *syntactically* optional: the `verification` group below refuses it, and
    # every other command is refused right after parsing (still exit 2) when the operator leaves it
    # out. Making it `required=True` would put the flag on the group that must never name a file.
    parser.add_argument('--database', type=Path)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('status')
    sub.add_parser('migrate', help=f'apply migrations up to schema v{VERSION}, after a verified copy')
    backup = sub.add_parser('backup')
    backup.add_argument('--output', type=Path, required=True)
    intake = sub.add_parser('intake')
    intake.add_argument('--source', required=True)
    intake.add_argument('--event', type=Path, required=True)
    intake.add_argument('--index', type=Path,
                        help='a built inventory index; when given, the event is admitted through the '
                             'same grouping the HTTP routes use, and when omitted the event opens its '
                             'own incident exactly as it did before grouping existed')
    detect = sub.add_parser('evaluate')
    detect.add_argument('--index', type=Path, required=True)
    detect.add_argument('--rule', type=Path, required=True)
    detect.add_argument('--sample', type=Path)
    detect.add_argument('--now', type=timestamp)
    drift = sub.add_parser('drift', help='compare a configuration snapshot tree with the digests this '
                                        'producer last reported, and file what moved as `drift` events')
    drift.add_argument('--config', type=Path, required=True,
                       help=f'JSON naming the snapshot tree and its artifacts; the looping worker '
                            f'reads the same document from ${configdrift.CONFIG_ENVIRONMENT}')
    drift.add_argument('--index', type=Path, required=True)
    drift.add_argument('--source', required=True,
                       help='producer identity stamped on the events; the worker reads the same '
                            f'value from ${configdrift.SOURCE_ENVIRONMENT}')
    drift.add_argument('--now', type=timestamp)
    drift.add_argument('--show-diff', action='store_true',
                       help='print the unified diff text too; off by default because a configuration '
                            'snapshot is exactly the kind of file that holds a credential')
    notify = sub.add_parser('notify', help='deliver one queued notification; sends only when --mode '
                                           '(or $LO_NOTIFICATION_MODE) says live')
    notify.add_argument('--url', help='channel endpoint; read only in live mode')
    notify.add_argument('--token-file', type=Path, help='file holding the channel token; read only in '
                                                        'live mode')
    notify.add_argument('--mode', choices=NOTIFICATION_MODES, default=None,
                        help=f'off | recording | live. Default: ${MODE_ENVIRONMENT}, then '
                             f'{DEFAULT_MODE}. live is never the default and needs the flag or the '
                             f'environment variable naming it')
    conditions_run = sub.add_parser('conditions', help='run one round of the sustained conditions: the '
                                                       '``for:`` machine, absence rules and learned bands '
                                                       '(``mode: band`` entries in the same document)')
    conditions_run.add_argument('--config', type=Path,
                                help='JSON naming the rules to judge (`rules`, each entry a static tier, '
                                     'an availability rule, an absence rule or a `mode: band` entry). '
                                     'Omitting it here is the off switch: nothing is read and nothing is '
                                     'filed. One round only: no looping producer reads this document yet, '
                                     'and no environment variable names it')
    conditions_run.add_argument('--cursor', type=Path,
                                help='this producer\'s own JSON cursor: the window it delivered and the '
                                     'events it still owes. Required with --config, because a verdict with '
                                     'nowhere to record what it owes is a verdict that can be lost')
    conditions_run.add_argument('--index', type=Path,
                                help='declared inventory index; every rule\'s resource must resolve in it')
    conditions_run.add_argument('--now', type=timestamp)
    pathcheck_run = sub.add_parser('pathcheck', help='run one round of the "is it me or them" verdict: '
                                                     'read the probe reports the operator\'s own engines '
                                                     'wrote, classify them across vantage points, and file '
                                                     'what the verdict changed')
    pathcheck_run.add_argument('--config', type=Path,
                               help=f'JSON naming one vantage point, its targets and the directory its '
                                    f'probe reports arrive in (the looping worker reads the same document '
                                    f'from ${pathcheck.CONFIG_ENVIRONMENT}). Omitting it here is the off '
                                    f'switch: nothing is read and nothing is filed. One round only')
    pathcheck_run.add_argument('--index', type=Path,
                               help='declared inventory index; the vantage point must resolve in it, and so '
                                    'must every report\'s, or its probes are excluded')
    pathcheck_run.add_argument('--source',
                               help='producer identity stamped on the verdict; required with --config, and '
                                    f'the worker reads the same value from ${pathcheck.SOURCE_ENVIRONMENT}')
    pathcheck_run.add_argument('--now', type=timestamp)
    escalate = sub.add_parser('escalate', help='advance unacknowledged incidents one rung, by filing an '
                                               'event: this command never sends a notification itself')
    escalate.add_argument('--config', type=Path,
                          help='JSON naming the chains (`chains`, each one a rule id and its ordered '
                               'rungs). Omitting it here is the off switch. One round only: no looping '
                               'producer reads this document yet')
    escalate.add_argument('--cursor', type=Path,
                         help='the durable stage counter, so a restart does not re-page from rung 1')
    escalate.add_argument('--source',
                          help='producer identity on the stage event, required with --config; it must not '
                               'start with "stage-", which the notification policy routes to a synthetic '
                               'sink, and it is not the identity that sends anything')
    escalate.add_argument('--now', type=timestamp)
    explain = sub.add_parser('rca', help='one round of the rule-floor explanation over the open '
                                        'incidents: candidate causes built from what is already on '
                                        'record, with no model and no query of its own')
    explain.add_argument('--config', type=Path,
                        help='JSON naming the round bounds (max_incidents, max_model_calls, '
                             'lookback_seconds, data_class). Omitting it here is the off switch: '
                             'nothing is read and nothing is written')
    explain.add_argument('--index', type=Path,
                        help='declared inventory index, read-only; without it the bundle says the '
                             'declaration and graph channels were unavailable rather than empty')
    explain.add_argument('--source',
                        help='identity written on the explanation record; required with --config, and '
                             'the only thing this command is allowed to write beside it')
    explain.add_argument('--now', type=timestamp)
    slo_run = sub.add_parser('slo', help='one round of the error budget: attainment and the multi-window '
                                        'fast-burn pair over the configured objectives, filed as '
                                        'conditions; like every other producer here, it never sends a '
                                        'notification itself')
    slo_run.add_argument('--config', type=Path,
                        help='JSON naming the objectives (`objectives`). Omitting it here is not an off '
                             'switch of its own: the looping worker\'s $'
                             f'{slo_alerts.CONFIG_ENVIRONMENT} is read next, and neither naming a file '
                             f'is off — nothing is read and nothing is filed')
    slo_run.add_argument('--cursor', type=Path,
                        help='this producer\'s own JSON cursor: the window it delivered and the events '
                             f'it still owes. Taken from ${slo_alerts.CURSOR_ENVIRONMENT} when omitted, '
                             'so the one-shot command and the worker share one state file')
    slo_run.add_argument('--index', type=Path,
                        help='declared inventory index; every objective\'s resource must resolve in it, '
                             'or the round refuses before any store read runs')
    slo_run.add_argument('--source',
                        help=f'producer identity on the events filed, required with a configuration and '
                             f'taken from ${slo_alerts.SOURCE_ENVIRONMENT} when omitted; intake refuses '
                             'an event whose source differs from the actor filing it')
    slo_run.add_argument('--now', type=timestamp)
    forecast_run = sub.add_parser('forecast', help='one round of trend models and time-to-threshold '
                                                   'predictions over the configured rules, filed as '
                                                   '`.predicted` conditions beside the ones that already '
                                                   'fired')
    forecast_run.add_argument('--config', type=Path,
                             help='JSON naming the rules to project (`rules`). Omitting it here falls '
                                  f'back to ${timetothreshold.CONFIG_ENVIRONMENT}; neither naming a '
                                  'file is off, and off files nothing')
    forecast_run.add_argument('--cursor', type=Path,
                              help='this producer\'s own JSON cursor, taken from the document\'s '
                                   f'`cursor` key or ${timetothreshold.CURSOR_ENVIRONMENT} when '
                                   'omitted: a verdict with nowhere to record what it owes is a verdict '
                                   'that can be lost')
    forecast_run.add_argument('--index', type=Path,
                              help='declared inventory index; every rule\'s resource must resolve in it')
    forecast_run.add_argument('--now', type=timestamp)
    # The verification group owns its whole syntax : one HTTPS endpoint, a
    # credential file, an operation and nothing else. Registered last so the local commands read first
    # in `--help`, and registered here rather than inline so this function stays one thing per module.
    verification_cli.add_parser(sub)
    verification_follower.add_parser(sub)
    args = parser.parse_args()
    # Answered here, immediately after parsing and before anything is opened, for two reasons (card
    # #123's client slice). The group is HTTPS-only, so a `--database` on it is a conflict and not a
    # default to ignore -- `parser.error` says so and exits 2 before one file is read. And everything
    # from here down consults operational configuration the group must never touch: `notification_mode`
    # reads $LO_NOTIFICATION_MODE, `NotificationPolicy` and `Store` then open the operator's file. Every
    # other command still gets the refusal it always gave, one exit status, just a little later.
    if args.command == 'verify-follow':
        if args.database is not None:
            parser.error('verify-follow uses HTTPS only; it takes no --database')
        return verification_follower.schedule(args.config, loop=args.loop, interval=args.interval)
    if args.command == 'verification':
        if args.database is not None:
            parser.error('verification reads and submits over HTTPS only; it takes no --database')
        return verification_cli.run(args)
    if args.database is None:
        parser.error('the --database option is required')
    try:
        # Resolved before the store opens: the mode is part of how the policy is built, and an
        # unrecognised one must refuse on the JSON contract rather than as a traceback.
        mode = notification_mode(args.mode) if args.command == 'notify' else None
        policy = NotificationPolicy(delivery_mode=mode) if mode is not None else None
        # Only the migrate command may change an existing database by being pointed at it.
        store = Store(args.database, policy, migrate=args.command == 'migrate')
        if args.command == 'status':
            result = store.status()
        elif args.command == 'migrate':
            if store.migrated_from is None:
                result = {'status': 'current', 'version': VERSION, 'backup': None}
            else:
                result = {'status': 'migrated', 'from': store.migrated_from, 'to': VERSION,
                          'backup': str(store.migration_backup)}
                log.info('Schema migrations applied', extra={'from_version': store.migrated_from,
                                                             'to_version': VERSION,
                                                             'migrations': VERSION - store.migrated_from})
        elif args.command == 'backup':
            store.backup(args.output)
            result = {'status': 'backed_up'}
        elif args.command == 'intake':
            # `--index` closes the gap correlation followups left open: this was the one intake site that grouped
            # nothing,
            # because the subcommand named no inventory index and `Store.grouping_admission` answers
            # `None` for one. The flag is optional rather than required because filing one event without a
            # graph is a legitimate thing to want (and every installation that declared no topology still
            # gets it), so the absence is a choice and not an oversight — and it is the behaviour that
            # predates grouping, unchanged, which `tests/test_correlation.py::CliGroupingTests` pins from
            # both sides. When the flag is given the call is the shape the six producer rounds above use:
            # one `clock()` for the round, shared by the intake and the admission, so the event, its
            # incident, the member row and both audit rows all carry the same instant.
            actor = Actor(args.source, 'producer')
            if args.index is None:
                result = store.intake(read_document(args.event), actor)
            else:
                now = clock()
                result = store.intake(read_document(args.event), actor, now=now,
                                      admission=store.grouping_admission(args.index, actor, now=now))
        elif args.command == 'evaluate':
            now = clock(args.now)
            rule = read_document(args.rule)
            sample = read_document(args.sample) if args.sample else None
            actor = Actor(rule['source'], 'producer')
            events = evaluate(args.index, rule, sample, now=now)
            if sample:
                store.put_evidence(sample, actor, now=now)
            # `evaluate` requires its index, so the graph grouping reads is the same file the detection
            # resolved its resource against — one declared plane for one round, judged twice from one file.
            result = {'events': [store.intake(item, actor, now=now,
                                            admission=store.grouping_admission(args.index, actor, now=now))
                                 for item in events]}
        elif args.command == 'drift':
            # One round of the same producer `python -m local_observe.platform.configdrift` loops: the
            # same tree, the same cursor, the same refusals. The difference is the exit — this writes
            # into the database in front of the operator, so the producer token is not involved, and it
            # advances the cursor only for events intake has already accepted.
            config = configdrift.load_config(args.config)
            now = clock(args.now)
            actor = Actor(args.source, 'producer')
            filed: list[dict[str, Any]] = []

            def deliver(item: dict[str, Any]) -> None:
                filed.append(store.intake(item, actor, now=now,
                                          admission=store.grouping_admission(args.index, actor, now=now)))

            summary = configdrift.tick(args.index, config, config['cursor'], deliver, now=now,
                                       source=args.source)
            for evaluation in summary['evaluations']:
                if not args.show_diff:
                    # Digests and counts are safe to print; the diff is configuration content.
                    evaluation.pop('diff', None)
            result = {'status': summary['result'], 'window': summary['window'],
                      'changed': summary['changed'], 'baselined': summary['baselined'],
                      'unreadable': summary['unreadable'], 'events': filed,
                      'evaluations': summary['evaluations']}
        elif args.command == 'conditions':
            # One round of the same producer `python -m local_observe.platform.conditions` will loop when
            # a manifest ships it: the same document, the same cursor, the same refusals. The difference
            # is the exit — this files into the database in front of the operator, so no producer token is
            # involved, and each event is intaken under the source its own rule names.
            if args.config is None:
                log.info('Conditions round not configured', extra={'reason': 'no --config named'})
                result = {'status': 'off', 'configured': False}
            else:
                for name in ('cursor', 'index'):
                    if getattr(args, name) is None:
                        raise ValueError(f'conditions --{name} is required with --config')
                require_cursor_parent(args.cursor)
                document = conditions.load_config(args.config)
                store_document = conditions.load_cursor(args.cursor, document)
                filed: list[dict[str, Any]] = []
                # One instant for the round, taken once instead of at every call: grouping's audit row and
                # intake's own rows are only the same decision if they carry the same timestamp, and three
                # separate `clock()` calls on an un-injected round could differ.
                moment = clock(args.now)

                def deliver_conditions(item: dict[str, Any]) -> None:
                    # Each event is filed by the source its own rule names: intake requires
                    # `event.source == actor.identity`, and this rule set may hold more than one producer.
                    producer = Actor(item['source'], 'producer')
                    filed.append(store.intake(item, producer, now=moment,
                                              admission=store.grouping_admission(args.index, producer,
                                                                                 now=moment)))

                summary = conditions.tick(args.index, document, args.cursor, store_reader(),
                                         deliver_conditions, now=moment, state=store_document)
                result = {'status': summary['result'], 'rules': summary['rules'],
                          'events': summary['events'], 'refusals': summary['refusals'],
                          'intake': filed}
        elif args.command == 'pathcheck':
            # One round of the same producer `python -m local_observe.platform.pathcheck` loops: the same
            # vantage point, the same reports directory, the same cursor, the same refusals. The
            # difference is the exit — this files into the database in front of the operator, so no
            # producer token is involved, and the route findings it prints are reported state rather than
            # events: `vocabulary.REFUSALS` gives a bare route change no `kind` (event vocabulary), so nothing here
            # POSTs one.
            if args.config is None:
                log.info('Pathcheck round not configured', extra={'reason': 'no --config named'})
                result = {'status': 'off', 'configured': False}
            else:
                for name in ('index', 'source'):
                    if getattr(args, name) is None:
                        raise ValueError(f'pathcheck --{name} is required with --config')
                config = pathcheck.load_config(args.config)
                require_cursor_parent(config['cursor'])
                now = clock(args.now)
                actor = Actor(args.source, 'producer')
                filed = []

                def deliver_pathcheck(item: dict[str, Any]) -> None:
                    filed.append(store.intake(item, actor, now=now,
                                              admission=store.grouping_admission(args.index, actor, now=now)))

                summary = pathcheck.tick(args.index, config, config['cursor'], deliver_pathcheck,
                                         now=now, source=args.source)
                result = {'status': summary['result'], 'window': summary['window'],
                          'verdict': summary['verdict'], 'notes': summary['notes'],
                          'affected': summary['affected'], 'failing': summary['failing'],
                          'open_finding': summary['open_finding'], 'intake': filed,
                          'observations': summary['observations'],
                          'route_findings': summary['route_findings'],
                          'excluded_undeclared_vantage': summary['excluded_undeclared_vantage'],
                          'unparseable_reports': summary['unparseable_reports'],
                          'stale_reports': summary['stale_reports'], 'blind': summary['blind']}
        elif args.command == 'escalate':
            # No channel client, no mode flag, no `--url`: escalation enqueues verdicts and the delivery
            # rail decides what they cost. That separation is the point of the subcommand, and it is the
            # reason `live` is not reachable from here at all.
            if args.config is None:
                log.info('Escalation not configured', extra={'reason': 'no --config named'})
                result = {'status': 'off', 'configured': False}
            else:
                for name in ('cursor', 'source'):
                    if getattr(args, name) is None:
                        raise ValueError(f'escalate --{name} is required with --config')
                require_cursor_parent(args.cursor)
                chains = escalation.config(args.config)['chains']
                result = escalation.tick(store, args.cursor, chains=chains, source=args.source,
                                        now=clock(args.now))
        elif args.command == 'rca':
            # One round of the rule floor, written through this store and no other path. Three things
            # this command does not do, each of which is the temptation of a component like this one:
            # it files no event (so it opens no incident and books no delivery), it issues no query (the
            # only telemetry it can show is an evidence row the platform still holds), and it never
            # constructs the optional AI client — `generate` stays None here, so the rule floor answers
            # on its own and the `ai` package remains nothing this process imports.
            if args.config is None:
                log.info('RCA round not configured', extra={'reason': 'no --config named'})
                result = {'status': 'off', 'configured': False, 'analyzed': 0}
            else:
                if args.source is None:
                    raise ValueError('rca --source is required with --config')
                result = rca.tick(store, args.index, config=rca.load_config(args.config),
                                  source=args.source, now=clock(args.now))
        elif args.command == 'slo':
            result = slo_round(store, args)
        elif args.command == 'forecast':
            result = forecast_round(store, args)
        elif args.command == 'notify':
            # Two orders matter here (ledger notification and state leftovers, from the test tooling review). The
            # channel arguments are
            # settled first so a live run with nowhere to send cannot end up recording `live` as this
            # database's mode. Then the gate the API's lifespan applies and this entry point skipped:
            # `start_notification_mode` is what writes `notification_control.mode` and what refuses a
            # live startup over a backlog left paused under `off`/`recording`. Without it a `--mode
            # live` run sent anyway, which is precisely the transition the gate exists for.
            check_channel(args, mode)
            store.start_notification_mode()
            result = deliver_one(store, sender(args, mode))
        else:  # pragma: no cover - argparse rejects an unknown subcommand before this point
            raise ValueError(f'Unsupported command {args.command}')
        print(json.dumps(result, indent=2))
        return 0
    # sqlite3.Error joins the tuple for `drift`: it opens the inventory index, and a missing or unreadable
    # index is an OperationalError, which is not an OSError. Without it that refusal escapes as a
    # traceback instead of the JSON line this CLI's contract promises on stdout.
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error) as exc:
        # stdout keeps its machine-readable JSON contract; the diagnosis goes to the log stream.
        log.warning('Platform command failed', extra={'command': args.command, 'error_class': type(exc).__name__})
        log.debug('Platform command details', exc_info=True)
        print(json.dumps({'status': 'error', 'error_type': type(exc).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

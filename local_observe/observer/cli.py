"""Local OS-authenticated observer commands. Structured logs never include evidence bodies."""
from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
import secrets
import sys

from .contract import Config, ObserverError, encoded, instant, require, strict_json
from .environment import load_environment
from .journal import Journal
from .runtime import CycleDeadline, Observer


def read_json(path: str, limit: int = 65536):
    with Path(path).open('rb') as stream:
        return strict_json(stream.read(limit + 1), limit)


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def delivery_arguments(parser):
    parser.add_argument('--channel', help='protected recording/Telegram channel JSON')
    parser.add_argument('--acceptance', help='protected human quality acceptance receipt')
    parser.add_argument('--report', help='exact protected evaluation report accepted by the human')


def delivery_session(args, journal, config, model):
    if not args.channel:
        return None
    from .delivery import DeliverySession, read_channel
    channel = read_channel(args.channel)
    if channel is None:
        return None
    require(bool(args.acceptance and args.report), 'accepted_quality_artifacts_required')
    return DeliverySession(journal, config, model, channel, acceptance_path=args.acceptance,
                           report_path=args.report, now=now_utc())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True, help='owned 0700 directory outside source control')
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('run', 'serve'):
        action = commands.add_parser(command)
        action.add_argument('--config', required=True)
        action.add_argument('--environment', help='protected allowlisted environment JSON; no shell or ambient merge')
        delivery_arguments(action)
        if command == 'run':
            action.add_argument('--cycle-id')
            action.add_argument('--now', help='explicit UTC observation window end for replayable local runs')
    check = commands.add_parser('check')
    check.add_argument('--max-age-seconds', type=int, default=7200)
    # The other half of `POST /v1/observer/runs`: an admitted cycle is run here, by the process that can
    # hold the journal's lock, own the model route and carry a wall-clock deadline on its main thread.
    drain = commands.add_parser('drain', help='claim and run the cycles another surface admitted')
    drain.add_argument('--config', required=True)
    drain.add_argument('--environment', help='protected allowlisted environment JSON; no shell or ambient merge')
    drain.add_argument('--limit', type=int, default=4,
                       help='at most this many admitted cycles per invocation; idle is an answer, not an error')
    replay = commands.add_parser('replay')
    replay.add_argument('cycle_id')
    feedback = commands.add_parser('feedback')
    feedback.add_argument('cycle_id')
    feedback.add_argument('--id', required=True)
    feedback.add_argument('--input', required=True, help='JSON with independent human review fields')
    retrieve = commands.add_parser('retrieve')
    retrieve.add_argument('--query', default='')
    retrieve.add_argument('--limit', type=int, default=10)
    export = commands.add_parser('export')
    export.add_argument('--output', required=True, help='new file within the private state directory')
    export.add_argument('--limit', type=int, default=100)
    backup = commands.add_parser('backup')
    backup.add_argument('--output', required=True, help='new database within the private state directory')
    for command in ('quality-accept', 'quality-revoke', 'deliver'):
        action = commands.add_parser(command)
        action.add_argument('--config', required=True)
        action.add_argument('--environment')
        delivery_arguments(action)
        if command == 'quality-accept':
            action.add_argument('--expires-at', required=True)
            action.add_argument('--output', required=True)
            action.add_argument('--attest-independent-held-out-labels', action='store_true')
        elif command == 'deliver':
            action.add_argument('cycle_id', help='new cycle identity; pre-reconciliation cycles cannot send')
            action.add_argument('--used-today-floor', type=int,
                                help='human-confirmed model sends today; omission defers until next UTC day')
    commands.add_parser('delivery-status')
    commands.add_parser('disarm')
    reconcile_parser = commands.add_parser('reconcile')
    reconcile_parser.add_argument('--session', required=True)
    reconcile_parser.add_argument('--epoch', required=True)
    reconcile_parser.add_argument('--attest-external-effects-reconciled', action='store_true')
    reconcile_parser.add_argument('--used-today-floor', type=int)
    args = parser.parse_args(argv)
    journal = None
    try:
        journal = Journal(args.state)
        if args.command in ('run', 'serve'):
            config = Config.from_dict(read_json(args.config))
            environment = load_environment(args.environment)
            fixed = instant(args.now) if args.command == 'run' and args.now else None
            observer = Observer(config, journal, clock=(lambda: fixed) if fixed else None, environ=environment)
            try:
                channel = delivery_session(args, journal, config, observer.model)
                status = channel.status(now_utc()) if channel is not None else None
            except (CycleDeadline, Exception):
                from .delivery import UnavailableDelivery
                channel = UnavailableDelivery(journal, now=now_utc())
                status = channel.status(now_utc())
            if status is not None:
                print(encoded(status), flush=True)
            if args.command == 'serve':
                observer.serve(delivery=channel, on_delivery=lambda result: print(encoded(result), flush=True))
                return 0
            result = observer.run(args.cycle_id)
            print(encoded({key: result[key] for key in ('cycle_id', 'status', 'coverage', 'decision', 'error',
                                                       'ended_at', 'delivery')}))
            if channel is not None:
                print(encoded(channel.tick(cycle=result, now=now_utc())))
            return 0 if result['status'] == 'completed' else 2
        if args.command in ('quality-accept', 'quality-revoke', 'deliver'):
            from .acceptance import AcceptedQuality, accept_quality
            from .adapters import Model
            from .delivery import read_channel, reconcile
            config = Config.from_dict(read_json(args.config))
            model = Model(environ=load_environment(args.environment))
            require(bool(args.channel), 'delivery_channel_required')
            channel_config = read_channel(args.channel)
            require(channel_config is not None, 'delivery_channel_required')
            if args.command == 'quality-accept':
                require(bool(args.report), 'quality_report_required')
                receipt = accept_quality(journal, report_path=args.report, config=config, model=model,
                    channel=channel_config, output=args.output, expires_at=args.expires_at,
                    independent_held_out_labels=args.attest_independent_held_out_labels, now=now_utc())
                print(encoded({'accepted': True, 'sha256': receipt['sha256'], 'actor': receipt['actor']}))
            elif args.command == 'quality-revoke':
                require(bool(args.acceptance), 'acceptance_required')
                quality = AcceptedQuality(args.acceptance, args.report, journal=journal,
                                           config=config, model=model, channel=channel_config)
                print(encoded(quality.revoke(now=now_utc())))
            else:
                session = delivery_session(args, journal, config, model)
                require(sys.stdin.isatty(), 'interactive_reconciliation_required')
                print(encoded(session.status(now_utc())), flush=True)
                confirmed = input('After reconciling previous external effects, type session '
                                  + session.session_id + ': ')
                require(confirmed == session.session_id, 'external_effect_reconciliation_required')
                import uuid
                reconcile(journal, session_id=session.session_id, epoch=str(uuid.uuid4()), attested=True, now=now_utc(),
                          used_today_floor=args.used_today_floor)
                require(journal.get(args.cycle_id) is None, 'pre_reconciliation_cycle_refused')
                activation = session.tick(now=now_utc(), poll=False)
                require(activation['state'] == 'armed', 'delivery_not_armed')
                observer = Observer(config, journal, model=model,
                                    environ=load_environment(args.environment), clock=now_utc)
                cycle = observer.run(args.cycle_id)
                outcome = session.tick(cycle=cycle, now=now_utc())
                print(encoded(outcome))
                return 0 if (outcome['state'] == 'armed'
                             and outcome.get('delivery', {}).get('status') not in ('deferred', 'uncertain')) else 2
            return 0
        if args.command in ('delivery-status', 'reconcile', 'disarm'):
            from .delivery import disarm, reconcile, session_status
            if args.command == 'reconcile':
                result = reconcile(journal, session_id=args.session, epoch=args.epoch,
                                   attested=args.attest_external_effects_reconciled, now=now_utc(),
                                   used_today_floor=args.used_today_floor)
            elif args.command == 'disarm':
                result = disarm(journal, now=now_utc())
            else:
                result = session_status(journal)
            print(encoded(result))
            return 0
        if args.command == 'drain':
            # One pass over the admitted queue, then exit: a deployment puts this on a timer, and a
            # long-lived claimer would be `serve` with a different name. The claim happens under the
            # journal's own lock and the cycle runs outside it, because `Observer.run` takes that lock
            # itself; the worker identity is per process, so a claim this drainer lost is visible as
            # somebody else's `running` row rather than as two processes in one cycle.
            # Read here and not at module scope: the queue lives beside the platform's HTTP boundary, and
            # the observer reaches `local_observe.platform` from exactly one other place, for the same
            # reason — a command that does not drain must not pay for it or fail on it.
            from local_observe.platform import job_queue
            require(1 <= args.limit <= 100, 'invalid_drain_bound')
            config = Config.from_dict(read_json(args.config))
            environment = load_environment(args.environment)
            observer = Observer(config, journal, environ=environment)
            worker = f'os-uid:{os.getuid()}:' + secrets.token_hex(6)
            outcome = []
            for _attempt in range(args.limit):
                with journal.lock() as acquired:
                    require(acquired, 'observer_busy')
                    job = job_queue.claim(journal.db, kind=job_queue.KIND_RUN, worker=worker, now=now_utc())
                if job is None:
                    break
                try:
                    cycle = observer.run(job['argument']['cycle_id'])
                except Exception as exc:
                    # The job closes with what the runner could do, never with the exception text: a
                    # transport message can carry a payload, and a job row is retained state.
                    job_queue.finish(journal.db, job_id=job['job_id'], worker=worker, status='failed',
                                error=str(exc) if isinstance(exc, ObserverError) else 'cycle_failed',
                                now=now_utc())
                    raise
                job_queue.finish(journal.db, job_id=job['job_id'], worker=worker, status='succeeded',
                            result={key: cycle[key] for key in
                                    ('cycle_id', 'status', 'coverage', 'decision', 'error', 'ended_at')},
                            now=now_utc())
                outcome.append({'job_id': job['job_id'], 'cycle_id': cycle['cycle_id'],
                                'status': cycle['status'], 'coverage': cycle['coverage'],
                                'decision': cycle['decision'], 'error': cycle['error']})
            print(encoded({'schema_version': 1, 'drained': len(outcome), 'cycles': outcome}))
            return 0
        if args.command == 'check':
            result = journal.check(now=dt.datetime.now(dt.timezone.utc), max_age_seconds=args.max_age_seconds)
            print(encoded(result))
            return 0 if result['healthy'] else 2
        if args.command == 'replay':
            print(encoded(journal.replay(args.cycle_id)))
        elif args.command == 'feedback':
            result = journal.feedback(args.cycle_id, args.id, read_json(args.input, 16384))
            print(encoded(result))
        elif args.command == 'retrieve':
            print(encoded(journal.examples(query=args.query, limit=args.limit)))
        elif args.command == 'export':
            target = Path(args.output)
            if target.parent.resolve() != journal.directory.resolve():
                raise ObserverError('export_must_be_in_private_directory')
            examples = journal.examples(limit=args.limit)
            fd = journal.create_file(target)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                for example in examples:
                    stream.write(encoded(example) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            print(encoded({'exported': len(examples), 'schema_version': 1}))
        elif args.command == 'backup':
            journal.backup(args.output)
            print(encoded({'backup': 'verified'}))
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(encoded({'error': str(exc) if isinstance(exc, ObserverError) else 'observer_command_failed'}),
              file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        if journal is not None:
            journal.close()


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())

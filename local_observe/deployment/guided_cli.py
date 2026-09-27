"""Authenticated client for reviewable setup; role authority stays at the platform API."""
import argparse
import json
from pathlib import Path
import sys

from local_observe.credentials import read_credential
from local_observe.http import JsonClient


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='trusted HTTPS platform endpoint')
    parser.add_argument('--token-file', required=True, help='credential for this caller, never a profile field')
    commands = parser.add_subparsers(dest='command', required=True)
    plan = commands.add_parser('plan')
    plan.add_argument('--profile', type=Path, required=True)
    decision = commands.add_parser('decision')
    decision.add_argument('plan_id')
    decision.add_argument('--decision', choices=('approved', 'denied'), required=True)
    decision.add_argument('--expires-at', required=True)
    for command in ('request', 'apply', 'verify'):
        commands.add_parser(command).add_argument('plan_id')
    args = parser.parse_args(argv)
    try:
        from local_observe.platform.runner_handoff import strict_request
        if args.command == 'plan':
            with args.profile.open('rb') as stream:
                body = {'profile': strict_request(stream.read(65537))}
        elif args.command == 'decision':
            body = {'plan_id': args.plan_id, 'decision': args.decision, 'expires_at': args.expires_at}
        else:
            body = {'plan_id': args.plan_id}
        token = read_credential('LO_GUIDED_CALLER', environ={'LO_GUIDED_CALLER_FILE': args.token_file})
        client = JsonClient(args.url, token)
        status, result = client.request('POST', '/v1/setup/' + args.command, body)
        if status != 200 or not isinstance(result, dict):
            print(json.dumps({'status': 'refused', 'http_status': status}), file=sys.stderr)
            return 2
        # The API returns plan/status/receipt only; credentials are never accepted from it.
        permitted = {'plan_id', 'plan', 'status', 'preflight', 'files', 'runner', 'approver', 'destination'}
        if set(result) - permitted:
            raise ValueError('Unexpected setup response')
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'status': 'refused', 'reason': 'setup_request_failed'}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())

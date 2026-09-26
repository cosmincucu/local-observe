#!/usr/bin/env python3
"""The operator's CLI for the owned ``security_events`` store (security store).

Read-only except ``apply-schema``, and ``apply-schema`` is idempotent by construction (every
statement is ``IF NOT EXISTS``). Nothing here ever alters a table: the TTL the store declares and the
TTL the table carries are compared and reported, and closing the gap is an operator's decision about
an ``ALTER``, not a side effect of running a checker.

    python -m local_observe.security.cli print-schema     # the DDL, no credential, no network
    python -m local_observe.security.cli apply-schema      # send that DDL (needs DDL rights)
    python -m local_observe.security.cli count             # distinct findings in the owned table
    python -m local_observe.security.cli verify-ttl         # declared TTL == live table TTL?
    python -m local_observe.security.cli verify-backup      # is the table inside what gets copied?

Exit status follows the one convention this repository already uses for its store tooling
(``components/data/store-signoz/retention.py``): **0** agrees, **1** the store disagrees (drift, no
TTL, a table the backup does not cover), **2** the question could not be answered (unreachable store,
missing credential, no data directory named). "Could not read" is never reported as agreement.

Environment: ``LO_SECURITY_CLICKHOUSE_URL``, ``LO_SECURITY_CLICKHOUSE_USER`` (default ``lo-security``,
the user proposed in ``clickhouse-users.d/CONTRACT.md``) and the credential
``LO_SECURITY_CLICKHOUSE_PASSWORD`` — which must arrive as ``LO_SECURITY_CLICKHOUSE_PASSWORD_FILE``
in any container, the same rule every other credential in this product follows
(``local_observe/credentials.py``). ``LO_SECURITY_EVENTS_DATA_ROOT`` names the ClickHouse data
directory for ``verify-backup``; there is no default for it, on purpose (see `backup.py`).
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from local_observe.credentials import read_credential
from local_observe.security import backup
from local_observe.security.schema import ddl_statements
from local_observe.security.store import (ClickHouseSecurityReader, ClickHouseSecurityWriter,
                                         SecurityEventStore, SecurityStoreRefused)

DEFAULT_USER = 'lo-security'
ENV_URL = 'LO_SECURITY_CLICKHOUSE_URL'
ENV_USER = 'LO_SECURITY_CLICKHOUSE_USER'
ENV_PASSWORD = 'LO_SECURITY_CLICKHOUSE_PASSWORD'
ENV_ALLOW_HTTP = 'LO_INTERNAL_ALLOW_HTTP'


def _environment(environ: Any = None) -> Any:
    """Return the mapping this command should read, defaulting to the process environment."""
    return os.environ if environ is None else environ


def build_store(environ: Any = None) -> SecurityEventStore:
    """Build the store from the environment: one credential, one writer and one reader over it.

    The reader is store facade's bounded client (``readonly = 1`` on every request, seven server-side bounds,
    64 KiB response cap), so the three aggregates this CLI reads are asked the same way the platform
    asks its other reads; the writer is the separate minimal transport. They share a credential here
    because this CLI is one operator command, not the runner's long-lived identity —
    ``components/data/store-signoz/clickhouse-users.d/CONTRACT.md`` states what that one user must
    hold, which is a proposal pending a reviewer's decision.
    """
    from local_observe.store.backends.clickhouse import ClickHouse

    values = _environment(environ)
    url = values.get(ENV_URL)
    if not url:
        raise SecurityStoreRefused(f'{ENV_URL} is not set: name the ClickHouse endpoint, or use '
                                   f'"print-schema" to see the DDL without a store')
    allow_http = values.get(ENV_ALLOW_HTTP) == '1'
    user = values.get(ENV_USER) or DEFAULT_USER
    password = read_credential(ENV_PASSWORD, environ=values)
    return SecurityEventStore(writer=ClickHouseSecurityWriter(url, user, password, allow_http=allow_http),
                              reader=ClickHouseSecurityReader(ClickHouse(url, user, password,
                                                                         allow_http=allow_http)))


def _print_schema(args: argparse.Namespace) -> int:
    """Print the owned DDL to stdout and require nothing: no endpoint, no credential, no network.

    stdout is only ever SQL, so `... print-schema | clickhouse-client` works; the two advisory lines
    go to stderr, where they cannot be piped into a server.
    """
    for statement in ddl_statements():
        print(statement)
        print()
    print('# idempotent (IF NOT EXISTS); applied by an operator, never by a worker on boot', file=sys.stderr)
    print('# applying it needs DDL rights, which the proposed lo-security user deliberately does NOT hold',
          file=sys.stderr)
    return 0


def _apply_schema(args: argparse.Namespace) -> int:
    """Send the DDL, then read the live table's TTL back and report whether it agrees."""
    try:
        verdict = build_store(args.environ).ensure_schema()
    except (SecurityStoreRefused, KeyError) as exc:
        print(f'cannot apply: {exc}', file=sys.stderr)
        return 2
    print(f'{len(verdict.statements)} statement(s) sent (IF NOT EXISTS)')
    print(f'TTL: {verdict.comparison.detail}')
    return 0 if verdict.comparison.matches else 1


def _count(args: argparse.Namespace) -> int:
    """Print the distinct finding count, or why it could not be read."""
    try:
        print(build_store(args.environ).count())
    except (SecurityStoreRefused, KeyError) as exc:
        print(f'cannot read: {exc}', file=sys.stderr)
        return 2
    return 0


def _verify_ttl(args: argparse.Namespace) -> int:
    """Report the declared-versus-live TTL verdict and the rows already past their deadline."""
    try:
        verdict = build_store(args.environ).verify_ttl()
    except (SecurityStoreRefused, KeyError) as exc:
        print(f'cannot read: {exc}', file=sys.stderr)
        return 2
    expired = ('unreadable' if verdict.expired < 0 else
               f'{verdict.expired} row(s) past their deadline (ClickHouse deletes on merge)')
    print(f'TTL {verdict.status}: {verdict.comparison.detail}; {expired}; checked {verdict.checked_at}')
    return 0 if verdict.comparison.matches else 1


def _verify_backup(args: argparse.Namespace) -> int:
    """Report whether the owned table sits inside the data directory the backup job copies."""
    try:
        verdict = backup.check(_environment(args.environ))
    except backup.BackupCoverageRefused as exc:
        print(f'cannot check: {exc}', file=sys.stderr)
        return 2
    print(verdict.detail)
    return 0 if verdict.ok else 1


def main(argv: list[str] | None = None, environ: Any = None) -> int:
    """Parse one command and return its exit status (0 agrees, 1 disagrees, 2 cannot answer)."""
    parser = argparse.ArgumentParser(prog='python -m local_observe.security.cli',
                                     description='The owned security_events store (security store)')
    sub = parser.add_subparsers(dest='command', required=True)
    handlers = {'print-schema': _print_schema, 'apply-schema': _apply_schema, 'count': _count,
                'verify-ttl': _verify_ttl, 'verify-backup': _verify_backup}
    for name, handler in handlers.items():
        command = sub.add_parser(name)
        command.set_defaults(func=handler)
    args = parser.parse_args(argv)
    args.environ = _environment(environ)
    return int(args.func(args))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

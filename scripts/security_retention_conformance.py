"""Read one fixed retention case on a separately provisioned disposable ClickHouse fixture."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from urllib.parse import urlsplit
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from local_observe.credentials import read_credential
from local_observe.http import TransportError
from local_observe.security.store import ClickHouseSecurityReader, SecurityEventStore
from local_observe.security.ttl import compare, table_ttl_expression
from local_observe.store.backends.clickhouse import ClickHouse

READER = 'lo-retention-conformance'
DENIED = 'lo-read'
IMAGE = 'sha256:10f54f04de6c61b756c4eaf9f1d17464a4ac3e1f94b5b410e0dec92a24dbeda8'
CASES = {'match': 'match', 'drift': 'drift', 'no-ttl': 'no-ttl', 'absent': 'unreadable',
         'extra-delete': 'unreadable', 'unsupported-ttl': 'unreadable', 'permission': 'unreadable',
         'bad-credential': 'unreadable'}
MARKER_SQL = ('SELECT fixture_id, case_name, image_digest FROM lo_retention_conformance.identity '
              'FORMAT JSON')
IDENTITY_SQL = 'SELECT version() AS version, currentUser() AS user FORMAT JSON'
METADATA_PARAMETERS = {'database': 'security_events', 'table': 'events'}
MAX_CONTRACT_BYTES = 8192
MAX_OUTPUT_BYTES = 16384


class Refused(ValueError):
    """Only fixed, safe categories leave this harness."""


def require(condition, category):
    if not condition:
        raise Refused(category)


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'contract_duplicate_field')
        result[key] = value
    return result


def contract(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_CONTRACT_BYTES + 1)
    require(len(raw) <= MAX_CONTRACT_BYTES, 'contract_size')
    value = json.loads(raw, object_pairs_hook=_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refused('contract_number')))
    require(isinstance(value, dict) and set(value) == {
        'schema_version', 'fixture_id', 'url', 'reader_password_file', 'denied_password_file'}, 'contract_fields')
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'contract_version')
    require(isinstance(value['fixture_id'], str)
            and str(UUID(value['fixture_id'])) == value['fixture_id'], 'contract_fixture_id')
    require(isinstance(value['url'], str), 'contract_url')
    parsed = urlsplit(value['url'])
    require(parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'
            and parsed.port is not None and 1024 <= parsed.port <= 65535
            and not parsed.username and not parsed.password and not parsed.query
            and not parsed.fragment and not parsed.path
            and value['url'] == f'http://127.0.0.1:{parsed.port}', 'contract_url')
    for key in ('reader_password_file', 'denied_password_file'):
        require(isinstance(value[key], str) and Path(value[key]).is_absolute(), 'contract_credential_path')
    require(value['reader_password_file'] != value['denied_password_file'], 'contract_shared_credential')
    return value


def password(path):
    candidate = Path(path)
    info = candidate.lstat()
    require(stat.S_ISREG(info.st_mode) and not candidate.is_symlink(), 'credential_not_regular')
    if os.name == 'posix':
        require(info.st_mode & 0o077 == 0, 'credential_permissions')
    return read_credential('LO_RETENTION_FIXTURE_PASSWORD', environ={
        'LO_RETENTION_FIXTURE_PASSWORD_FILE': str(candidate)})


class NoWriter:
    def execute(self, _statement):
        raise Refused('unexpected_write')


def _identity(client, user):
    row = client.query(IDENTITY_SQL, {})
    require(isinstance(row, dict) and set(row) == {'version', 'user'}
            and row['user'] == user and isinstance(row['version'], str)
            and len(row['version']) <= 32
            and re.fullmatch(r'25\.12\.5(?:\.\d+)?', row['version']) is not None, 'server_identity')
    return row


def _marker(client, config, case):
    row = client.query(MARKER_SQL, {})
    require(row == {'fixture_id': config['fixture_id'], 'case_name': case, 'image_digest': IMAGE},
            'fixture_marker')
    return row


def _metadata(client):
    row = client.query(ClickHouseSecurityReader.TTL_SQL, METADATA_PARAMETERS)
    require(isinstance(row, dict) and set(row) == {'table_count', 'create_table_query'}
            and type(row['table_count']) in (int, str)
            and row['table_count'] in (0, 1, '0', '1')
            and isinstance(row['create_table_query'], str), 'metadata_shape')
    return row


def observe(config, case, *, client_factory=ClickHouse):
    """Only literal read statements. The marker is a setup check, not isolation proof."""
    require(case in CASES, 'unknown_case')
    secret = password(config['reader_password_file'])
    guard = client_factory(config['url'], READER, secret, allow_http=True)
    identity = _identity(guard, READER)
    marker = _marker(guard, config, case)
    before = _metadata(guard)
    count = int(before['table_count'])
    require(count == (0 if case == 'absent' else 1), 'fixture_table_presence')
    ddl = before['create_table_query']
    # Confirm setup through the real returned DDL before interpreting a negative reader result.
    if count:
        require(ClickHouseSecurityReader(guard).count() == 0, 'fixture_not_empty')
        setup = compare(table_ttl_expression(ddl))
        expected_setup = 'match' if case in ('permission', 'bad-credential') else CASES[case]
        require(setup.status == expected_setup, 'fixture_ttl_setup')
        if case == 'drift':
            require(setup.live.critical_days == 1825 and setup.live.routine_days == 91, 'fixture_drift_setup')
        if case in ('extra-delete', 'unsupported-ttl'):
            expression = table_ttl_expression(ddl)
            if case == 'extra-delete':
                remaining, removed = re.subn(
                    r',\s*toDateTime\s*\(\s*ts\s*\)\s*\+\s*toIntervalDay\s*\(\s*1\s*\)(?:\s+DELETE)?\s*$',
                    '', expression, flags=re.I)
                require(removed == 1 and compare(remaining).matches,
                        'fixture_extra_delete_setup')
            else:
                restored, replaced = re.subn(r'\btoIntervalMonth\s*\(\s*1\s*\)',
                                             'toIntervalDay(90)', expression, flags=re.I)
                require(replaced == 1 and compare(restored).matches,
                        'fixture_unsupported_setup')
    target = guard
    if case == 'permission':
        denied_secret = password(config['denied_password_file'])
        require(denied_secret != secret, 'shared_credential')
        target = client_factory(config['url'], DENIED, denied_secret, allow_http=True)
        require(_identity(target, DENIED)['version'] == identity['version'], 'denied_server_identity')
    elif case == 'bad-credential':
        invalid = secrets.token_urlsafe(32)
        if invalid == secret:
            invalid += 'x'
        target = client_factory(config['url'], READER, invalid, allow_http=True)
        try:
            target.query(IDENTITY_SQL, {})
        except TransportError:
            pass
        else:
            raise Refused('invalid_credential_not_refused')
    verdict = SecurityEventStore(writer=NoWriter(), reader=ClickHouseSecurityReader(target)).verify_ttl()
    require(verdict.status == CASES[case], 'unexpected_verdict')
    require(verdict.expired == (-1 if case in ('absent', 'permission', 'bad-credential') else 0),
            'fixture_rows_or_read_failure')
    require(_metadata(guard) == before and _marker(guard, config, case) == marker, 'fixture_changed')
    result = {'schema_version': 1, 'case': case, 'success': True, 'fixture_id': config['fixture_id'],
              'server_version': identity['version'], 'reader': DENIED if case == 'permission' else READER,
              'fixture_declared_image_digest': IMAGE,
              'image_identity_scope': 'marker declaration; parent must verify actual container image and isolation',
              'status': verdict.status, 'expired_rows': verdict.expired, 'metadata_table_count': count,
              'ddl_utf8_bytes': len(ddl.encode()), 'ddl_sha256': hashlib.sha256(ddl.encode()).hexdigest(),
              'response_byte_cap': 65536, 'aggregate_row_cap': 1,
              'checked_at': verdict.checked_at}
    result['declared_days'] = {'critical': verdict.comparison.declared.critical_days,
                               'routine': verdict.comparison.declared.routine_days}
    live = verdict.comparison.live
    result['live_days'] = None if live is None else {'critical': live.critical_days, 'routine': live.routine_days}
    if case in ('permission', 'bad-credential'):
        result['negative_scope'] = ('unknown handling with negative credentials; transport failure is also possible; '
                                    'independent server authorization response and grant checks remain required')
    root = Path(__file__).resolve().parents[1]
    result['source_sha256'] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in (
        'scripts/security_retention_conformance.py', 'local_observe/security/store.py',
        'local_observe/security/ttl.py', 'local_observe/security/schema.py',
        'local_observe/store/backends/clickhouse.py')}
    # No arbitrary server DDL or detail is copied into the evidence.
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--contract', required=True, type=Path)
    parser.add_argument('--case', required=True, choices=CASES)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    # Reserve evidence before credentials or network work; refuse reuse rather than overwrite.
    with args.output.open('x', encoding='utf-8') as stream:
        try:
            config = contract(args.contract)
            result = observe(config, args.case)
        except Refused as exc:
            result = {'schema_version': 1, 'case': args.case, 'success': False, 'failure': str(exc)}
        except (OSError, ValueError, KeyError, TypeError, RecursionError, TransportError):
            result = {'schema_version': 1, 'case': args.case, 'success': False,
                      'failure': 'configuration_or_read_failed'}
        encoded = json.dumps(result, sort_keys=True)
        require(len(encoded.encode()) <= MAX_OUTPUT_BYTES, 'evidence_size')
        stream.write(encoded + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'case': args.case, 'success': result['success']}))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

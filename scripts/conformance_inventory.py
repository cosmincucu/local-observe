"""Exercise the inventory build/discovery/proposal/ASGI path using synthetic files."""
import argparse
import asyncio
import base64
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
from contextlib import closing
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib.report import write_report
from _lib.require import refuse_optimized, require
from local_observe.inventory import discovery, index
from local_observe.inventory.api import create_app
from local_observe.inventory.validation import read_document, timestamp

ROOT = Path(__file__).resolve().parents[1]


async def check_api(path, token):
    import httpx
    app = create_app(path, token)
    headers = {'Authorization': 'Bearer ' + token}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://inventory.test') as client:
        for url in ('/', '/inventory/resources.json', '/graphql/inventory?query={resources{nodes{id}}}'):
            for auth in ({}, {'Authorization': 'Bearer invalid'}):
                status = (await client.get(url, headers=auth)).status_code
                require(status == 401, 'Unauthenticated request was not refused: ' + url + ' returned ' + str(status))
        response = await client.get('/inventory/resources.json?_shape=objects', headers=headers)
        require(response.status_code == 200, 'Resource rows were not served: ' + str(response.status_code))
        require(len(response.json()['rows']) == 2, 'The synthetic index served the wrong row count')
        response = await client.get('/graphql/inventory', params={'query': '{resources {nodes {id name}}}'}, headers=headers)
        require(response.status_code == 200 and not response.json().get('errors'),
                'GraphQL failed: ' + str(response.status_code) + ' ' + response.text)
        require(len(response.json()['data']['resources']['nodes']) == 2,
                'GraphQL returned the wrong node count')
        require((await client.get('/inventory.json?sql=select+1', headers=headers)).status_code == 403,
                'The raw SQL endpoint was not forbidden')
        require((await client.post('/inventory/resources/-/insert', headers=headers,
                                  json={'name': 'forbidden'})).status_code == 405,
                'A write method was not refused')
        basic = base64.b64encode(('operator:' + token).encode()).decode()
        require((await client.get('/', headers={'Authorization': 'Basic ' + basic})).status_code == 200,
                'Browser basic auth did not authenticate')
    return {'missing_wrong_credentials': 'rejected', 'rest_rows': 2, 'graphql_rows': 2,
            'sql_endpoint': 'forbidden', 'write_methods': 'forbidden', 'browser_basic_auth': 'pass'}


def main():
    refuse_optimized()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'running', 'checks': {},
              'scope': ('synthetic inventory documents built, discovered, proposed and served by the ASGI app in '
                        'this process only: no live host was read and nothing was published')}
    report_path = args.output / 'report.json'
    now = timestamp('2026-09-06T12:01:00Z')
    try:
        path = args.output / 'inventory.db'
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        report['checks']['build'] = index.build(declared, path, 'synthetic-fixture', now=now)
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        observed = args.output / 'observed.db'
        snapshot = read_document(ROOT / 'examples/inventory/observed.yaml')
        require(discovery.ingest(observed, snapshot, now=now)['status'] == 'inserted',
                'The observed snapshot was not accepted on first ingest')
        require(discovery.ingest(observed, snapshot, now=now)['status'] == 'duplicate',
                'Replaying the observed snapshot was not recognised as a duplicate')
        fresh = discovery.drift(path, observed, ['synthetic-fixture'], now=now)
        require({item['kind'] for item in fresh['findings']} == {'changed', 'undeclared', 'coverage_incomplete'},
                'Fresh drift surfaced an unexpected finding kind')
        stale = discovery.drift(path, observed, ['synthetic-fixture'], now=now + dt.timedelta(hours=2))
        require([item['kind'] for item in stale['findings']] == ['source_stale'],
                'A stale source did not suppress the other findings')
        proposal = discovery.propose(path, observed, 'synthetic-fixture', 'new-service-001', args.output / 'proposal.json', now=now)
        require(proposal['status'] == 'needs_review', 'A discovery proposal was not review-only')
        require(hashlib.sha256(path.read_bytes()).hexdigest() == before,
                'Discovery or proposal changed the declared index')
        report['checks']['discovery'] = {'replay': 'idempotent', 'fresh_findings': len(fresh['findings']),
                                         'stale_absence': 'suppressed', 'proposal': 'review_only', 'index_unchanged': True}
        write_report(report_path, report, replace=True)
        report['checks']['api'] = asyncio.run(check_api(path, secrets.token_urlsafe(32)))
        backup = args.output / 'observed-backup.db'
        restored = args.output / 'observed-restored.db'
        with closing(sqlite3.connect(observed)) as source, closing(sqlite3.connect(backup)) as destination:
            source.backup(destination)
        with closing(sqlite3.connect(backup)) as source, closing(sqlite3.connect(restored)) as destination:
            source.backup(destination)
            require(destination.execute('PRAGMA integrity_check').fetchone()[0] == 'ok',
                    'The restored observed database fails its integrity check')
        require(discovery.drift(path, restored, ['synthetic-fixture'], now=now) == fresh,
                'Drift differs after a backup/restore of the observed database')
        require(discovery.ingest(restored, snapshot, now=now)['status'] == 'duplicate',
                'Replay against the restored database is not idempotent')
        report['checks']['observed_backup_restore'] = 'integrity, drift and replay pass'
        candidate = copy.deepcopy(declared)
        candidate['resources'][0]['name'] = 'probe-1-renamed'
        candidate_path = args.output / 'candidate' / 'inventory.db'
        candidate_path.parent.mkdir()
        index.build(candidate, candidate_path, 'synthetic-candidate', now=now)
        with index.readonly(candidate_path) as connection:
            resolved = index.resolve(connection, aliases=[{'type': 'host.id', 'value': 'synthetic-host-001'}])
            require(resolved['resource_id'] == declared['resources'][0]['id'],
                    'The candidate snapshot lost the resource UUID behind the renamed name')
        report['checks']['candidate_snapshot'] = 'name changed; UUID and existing alias retained'
        report['status'] = 'pass'
    finally:
        if report['status'] == 'running':
            report['status'] = 'fail'
        write_report(report_path, report, replace=True)
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()

"""Small continuous synthetic source for the isolated Sigma query path, not host discovery."""
import json
import os
from pathlib import Path
import time
import urllib.request
import uuid


def insert_query(row):
    # Omitted columns must use defaults, not require INSERT permission on the whole schema.
    columns = ('timestamp', 'id', 'body', 'resources_string', 'attributes_string')
    if set(row) != set(columns):
        raise ValueError('Unexpected synthetic insert columns')
    return 'INSERT INTO signoz_logs.logs_v2 (' + ', '.join(columns) + ') FORMAT JSONEachRow\n' + json.dumps(row)


def main():
    config = json.loads(Path('/private/source.json').read_text())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while True:
        try:
            mode = Path('/fixture/mode').read_text().strip()
            if mode not in ('positive', 'negative', 'absent'):
                raise ValueError('Unexpected synthetic mode')
            if mode != 'absent':
                row = {'timestamp': time.time_ns(), 'id': str(uuid.uuid4()),
                       'body': 'local-observe continuous Sigma synthetic fixture',
                       'resources_string': {'resource_id': config['resource_id']},
                       'attributes_string': {'event.dataset': 'linux.process_creation',
                                             'process.executable': '/opt/lo-fixture',
                                             'process.command_line': '--sigma-positive' if mode == 'positive' else '--ordinary-negative'}}
                query = insert_query(row)
                request = urllib.request.Request('http://clickhouse:8123/', data=query.encode(), method='POST',
                    headers={'X-ClickHouse-User': config['user'], 'X-ClickHouse-Key': config['password']})
                with opener.open(request, timeout=5) as response:
                    if response.status != 200:
                        raise ValueError('Fixture rejected')
        except (OSError, ValueError):
            print('Synthetic source unavailable', flush=True)
        time.sleep(10)


if __name__ == '__main__':
    main()

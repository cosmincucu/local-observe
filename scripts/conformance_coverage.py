"""Protocol, selected redaction and bounded-load checks against isolated staging."""
import argparse
import base64
import copy
import json
from pathlib import Path
import sys
import time
import uuid

from conformance_recovery import Demo, add_scope_arguments, command
from conformance_smoke import payloads, post, require_accepted


def records(samples):
    """Return the one metric data point, log record and span inside a synthetic payload."""
    return [samples['metrics']['resourceMetrics'][0]['scopeMetrics'][0]['metrics'][0]['gauge']['dataPoints'][0],
            samples['logs']['resourceLogs'][0]['scopeLogs'][0]['logRecords'][0],
            samples['traces']['resourceSpans'][0]['scopeSpans'][0]['spans'][0]]


def grpc_checks(demo, port=14317):
    """Send each signal over gRPC: unauthenticated calls must fail, authenticated ones must land."""
    sys.path.insert(0, str(demo.base / 'artifacts/test-python'))
    import grpc
    from google.protobuf.json_format import ParseDict
    from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest, ExportMetricsServiceResponse
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest, ExportLogsServiceResponse
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest, ExportTraceServiceResponse
    types = {'metrics': (ExportMetricsServiceRequest, ExportMetricsServiceResponse, 'metrics', 'Metrics'),
             'logs': (ExportLogsServiceRequest, ExportLogsServiceResponse, 'logs', 'Logs'),
             'traces': (ExportTraceServiceRequest, ExportTraceServiceResponse, 'trace', 'Trace')}
    samples, queries = payloads(uuid.uuid4().hex)
    span = records(samples)[2]
    for key in ('traceId', 'spanId'):
        span[key] = base64.b64encode(bytes.fromhex(span[key])).decode()
    with grpc.insecure_channel(f'127.0.0.1:{port}', options=[('grpc.enable_http_proxy', 0)]) as channel:
        for signal, (request_type, response_type, package, service) in types.items():
            call = channel.unary_unary(f'/opentelemetry.proto.collector.{package}.v1.{service}Service/Export',
                request_serializer=request_type.SerializeToString, response_deserializer=response_type.FromString)
            for metadata in ((), (('authorization', 'Bearer invalid-conformance-token'),)):
                try:
                    call(request_type(), metadata=metadata, timeout=10)
                except grpc.RpcError as exc:
                    if exc.code() not in (grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.PERMISSION_DENIED):
                        raise ValueError('Unexpected gRPC rejection: ' + exc.code().name)
                else:
                    raise ValueError('gRPC accepted missing/wrong token')
            response = call(ParseDict(samples[signal], request_type()),
                            metadata=(('authorization', 'Bearer ' + demo.token),), timeout=10)
            if response.HasField('partial_success') and response.partial_success.ByteSize():
                raise ValueError('gRPC partial success')
    demo.wait_counts(queries)
    demo.record('grpc', {'signals': 3, 'missing_and_wrong_token': 'rejected', 'valid_roundtrips': 'pass'})


def redaction(demo):
    """Require every contract-listed attribute key to be scrubbed while a positive control survives."""
    samples, queries = payloads(uuid.uuid4().hex)
    canary = 'secret_canary_' + uuid.uuid4().hex
    keys = ['password', 'api_key', 'authorization', 'http.request.header.authorization',
            'gen_ai.prompt', 'gen_ai.completion', 'gen_ai.request.prompt', 'gen_ai.response.completion',
            'gen_ai.input.messages', 'gen_ai.output.messages', 'llm.prompts', 'llm.completions',
            'llm.openai.prompt_text', 'llm.openai.messages']
    for record in records(samples):
        record['attributes'] = [{'key': key, 'value': {'stringValue': canary}} for key in keys]
        record['attributes'].append({'key': 'lo.keep', 'value': {'stringValue': 'keep_' + demo.run}})
    for signal, sample in samples.items():
        require_accepted(*post(demo.url + '/v1/' + signal, sample, demo.token))
    demo.wait_counts(queries)
    for signal, query in queries.items():
        # Metric sample rows do not carry attributes; use the matching time-series metadata.
        if signal == 'metrics':
            query = query.replace('distributed_samples_v4', 'distributed_time_series_v4')
        rows = demo.compose('exec', '-T', 'clickhouse', 'clickhouse-client', '--query',
                            query.replace('SELECT count()', 'SELECT *') + ' LIMIT 5 SETTINGS max_execution_time=10 FORMAT JSONEachRow')
        if canary in rows or 'keep_' + demo.run not in rows:
            raise ValueError('Redaction or positive control failed for ' + signal)
    demo.record('selected_redaction', {'signals': 3, 'deleted_keys': len(keys), 'positive_control': 'preserved',
                'body_resource_attributes': 'outside current redaction contract; not scrubbed'})


def load(demo):
    """Send a log burst sized by what was actually accepted, and record what the store took.

    The counts in the report are the posts accepted, the records each post carried and the rows the
    store returned - not the number the loop was aimed at.
    """
    samples, queries = payloads(uuid.uuid4().hex)
    logs = samples['logs']
    record = records(samples)[1]
    batch = [copy.deepcopy(record) for _ in range(100)]
    logs['resourceLogs'][0]['scopeLogs'][0]['logRecords'] = batch
    records_per_post = len(batch)
    start = time.monotonic()
    accepted_posts = 0
    for _ in range(100):
        require_accepted(*post(demo.url + '/v1/logs', logs, demo.token))
        accepted_posts += 1
    accepted_logs = accepted_posts * records_per_post
    counts = demo.wait_counts({'logs': queries['logs']}, expected=accepted_logs)
    ids = demo.compose('ps', '-q').split()
    stats = command(['docker', 'stats', '--no-stream', '--format', '{{json .}}', *ids])
    states = [json.loads(command(['docker', 'inspect', '--format',
              '{"name":{{json .Name}},"oom":{{json .State.OOMKilled}},"memory_limit":{{.HostConfig.Memory}},"restarts":{{.RestartCount}}}', cid])) for cid in ids]
    if any(state['oom'] for state in states):
        raise ValueError('A staging container was OOM-killed')
    demo.record('bounded_load', {'posts_accepted': accepted_posts, 'records_per_post': records_per_post,
                'accepted_logs': accepted_logs, 'stored_logs': counts['logs'],
                'seconds': round(time.monotonic()-start, 2),
                'stats_after_load': [json.loads(line) for line in stats.splitlines()], 'states': states,
                'limit': 'burst test, not sustained capacity or peak-memory proof'})
    ttl = demo.compose('exec', '-T', 'clickhouse', 'clickhouse-client', '--query',
        "SELECT database,name,create_table_query FROM system.tables WHERE database IN ('signoz_logs','signoz_metrics','signoz_traces') "
        "AND position(create_table_query, ' TTL ') > 0 SETTINGS max_execution_time=10 FORMAT JSONEachRow")
    rows = [json.loads(line) for line in ttl.splitlines()]
    demo.record('retention_schema', [{'database': row['database'], 'table': row['name'],
                  'ttl': row['create_table_query'].split(' TTL ', 1)[1].split(' SETTINGS ', 1)[0]} for row in rows])


def retention(demo):
    """Insert dated synthetic rows, force the store TTL, and require each one to be gone."""
    marker = 'lo-retention-' + demo.run
    def sql(statement):
        return demo.compose('exec', '-T', 'clickhouse', 'clickhouse-client', '--query', statement)
    fixtures = [
        ('signoz_logs.logs_v2', f"(timestamp, body) VALUES (1577836800000000000, '{marker}')",
         f"body = '{marker}'", "tuple(toDate('2020-01-01'), 15, 0)", 15),
        ('signoz_metrics.samples_v4', f"(unix_milli, metric_name) VALUES (1577836800000, '{marker}')",
         f"metric_name = '{marker}'", "tuple(toDate('2020-01-01'))", 30),
        ('signoz_traces.signoz_index_v3', f"(timestamp, trace_id) VALUES ('2020-01-01 00:00:00', '{demo.run}')",
         f"trace_id = '{demo.run}'", "tuple(toDate('2020-01-01'))", 15),
    ]
    # Old synthetic rows in their own dated partitions test the actual store TTLs.
    for table, values, predicate, partition, days in fixtures:
        sql('SYSTEM STOP TTL MERGES ' + table)
        try:
            sql(f'INSERT INTO {table} ' + values)
            query = f'SELECT count() FROM {table} WHERE ' + predicate
            before = int(demo.query(query))
            if before != 1:
                raise ValueError('Retention fixture was not visible before TTL work')
        finally:
            sql('SYSTEM START TTL MERGES ' + table)
        sql(f'ALTER TABLE {table} MATERIALIZE TTL IN PARTITION {partition} SETTINGS mutations_sync=1')
        after = int(demo.query(query))
        if after != 0:
            raise ValueError('Expired synthetic row remained after TTL materialization')
        demo.record('retention_expiry_' + table, {'before': before, 'after': after, 'retention_days': days,
                    'partition': '2020-01-01', 'forced_materialization': True,
                    'limitation': 'not elapsed-time scheduling or every derived table'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    add_scope_arguments(parser)
    args = parser.parse_args()
    demo = Demo(args.env_file, base=args.base, uid=args.uid, docker_root=args.docker_root)
    try:
        grpc_checks(demo)
        redaction(demo)
        load(demo)
        retention(demo)
        demo.report['status'] = 'pass'
    except Exception as exc:
        demo.report['status'] = 'fail'
        demo.report['error'] = type(exc).__name__ + ': ' + str(exc)
        raise
    finally:
        demo.save()
        print(json.dumps({'checkpoint': str(demo.directory), 'status': demo.report['status']}), flush=True)


if __name__ == '__main__':
    main()

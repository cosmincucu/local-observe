"""Bounded compiled-Sigma execution with durable exact-batch replay and coverage events.

The transport this module used to define now lives in ``local_observe/store/backends/clickhouse.py``
(store facade), where the store facade generalises it; the names are re-imported here so the runner, the
anomaly producer and their tests keep importing from the module they always did.

The analytical copy of a finding (security store) is an optional third leg, asked for only when a writer
credential is configured: ``security.record`` before delivery, one coverage event about the copy, and
a re-attempt while an undelivered batch is still owed. With no credential the runner behaves exactly
as it did — the absence is logged once at startup rather than reported as health.

The same module owns the one claim a rule pack makes about itself: ``measurement_report`` counts the
shipped artifacts and how many of them carry a measured false-positive rate, and reports the rest as
``unmeasured``. A rule that has never been counted is not "quiet", and the number an operator reads at
start is the honest one (notification budget). ``measurement_signal`` is that triple in the shape the operator
overview reads it from, so the number in the container log and the number on the portal are one number.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any
import uuid

from local_observe.credentials import read_credential
from local_observe.http import JsonClient, TransportError
from local_observe.inventory import index
from local_observe.inventory.validation import digest, timestamp, utc_text
from local_observe.log import get_logger
from local_observe.store.backends.clickhouse import ClickHouse, SERIES_MAX_POINTS
from .detection_worker import save
from .detections import event
from .owner import exclusive_owner

log = get_logger(__name__)

#: What a compiled rule may claim about its own false-positive rate, and the only two answers the
#: reporter gives. `unmeasured` is the fail-closed side: an artifact whose `measurement` block is
#: absent, malformed, incomplete or claims a status this module does not know is counted as unmeasured
#: and never as "zero findings, all clear". corpus eval's precision gate scores that count, so the direction
#: of an absent number has to be the pessimistic one (`docs/DECISIONS.md` notification budget).
MEASUREMENT_STATUSES = ('measured', 'unmeasured')
#: The five fields a `measured` claim must still carry when it reaches the runner. Re-checked here and
#: not trusted from the build: the runner reports to an operator, and a report that inherits a
#: half-filled block would be a measurement with one field missing.
MEASUREMENT_FIELDS = ('false_positives', 'window', 'population', 'measured_on', 'source')
#: The three numbers `measurement_report` returns and `measurement_signal` publishes, named once so the
#: headline and the observation cannot disagree about what was counted. `platform/overview.py` repeats
#: these three names rather than importing them — it must not pull a ClickHouse client into the serving
#: read path — and `tests/test_overview_sigma.py` reddens if either side renames one.
MEASUREMENT_TRIPLE = ('shipped', 'measured', 'unmeasured')
#: How long a published measurement stays believable on the operator overview. The triple is a property
#: of reviewed artifacts rather than of a live probe, so it ages far more slowly than the `jobs` and
#: `model` observations (120 s each) that share that document; past this bound `platform/overview.py`
#: reports `stale` with three nulls, which is the answer this repo gives every expired observation.
MEASUREMENT_MAX_AGE_SECONDS = 3600
#: Provenance sentence beside the number, so the tile says what it counted. It is deliberately not a
#: path: a deployed container sees its own one artifact at its own mount point, so the honest scope is
#: "the pack this process was given" and the whole-tree figure is the command in the component's
#: CONTRACT.md.
MEASUREMENT_SOURCE = 'Compiled artifacts in the rule pack this container was given'
#: The largest artifact **file** `artifact()` will read, in bytes — the bound on the container, not on the
#: SQL inside the artifact (that is the 65,536-character check further down the same function).
#: Measured 2026-09-10: the two committed artifacts in `examples/sigma/compiled/` are 1,993 and 1,959
#: bytes, and the largest JSON anywhere under `examples/` (log fixtures included) is 4,048 bytes, so this
#: is about 500x the biggest artifact this tree ships. Why that size: the pack is read more than once —
#: `main()` reads the one artifact this container is given, and since overview sigma producer
#: `platform/overview_worker.sigma_signal` opens a whole operator-mounted directory (up to
#: `SIGMA_ARTIFACT_MAX` = 64 files) every 30-second tick — so the worst case is 64 x 1 MiB = 64 MiB of
#: opened files, which fits the 256 MB `mem_limit` of `components/control/platform/compose.yaml` (the
#: overview worker runs in that container) even with the decoded objects on top. The size is checked on
#: `stat()` **before** the read, so a refusal never buffers the file at all.
ARTIFACT_MAX_BYTES = 1_048_576


def measurement_status(compiled: dict[str, Any]) -> dict[str, Any]:
    """One artifact's measurement verdict: `measured` with its count, or `unmeasured` with its reason.

    Read-only and total: every input shape lands in one of the two statuses, and the reason for the
    safe answer is always a sentence an operator can repeat. `compiled['measurement']` is written by
    `sigma_compile.measurement`, so anything malformed here is a hand-edited or stale artifact rather
    than a build product, which is exactly when a count must not be believed.
    """
    block = compiled.get('measurement')
    rule_id = str(compiled.get('rule_id', 'unknown'))
    if not isinstance(block, dict):
        return {'rule_id': rule_id, 'status': 'unmeasured',
                'reason': 'the artifact carries no measurement block'}
    if block.get('status') not in MEASUREMENT_STATUSES:
        return {'rule_id': rule_id, 'status': 'unmeasured',
                'reason': 'the artifact names a measurement status this build does not know'}
    if block['status'] == 'unmeasured':
        return {'rule_id': rule_id, 'status': 'unmeasured',
                'reason': str(block.get('reason') or 'the rule states no reason for being unmeasured')}
    count = block.get('false_positives')
    missing = [key for key in MEASUREMENT_FIELDS[1:] if not isinstance(block.get(key), str) or not block[key]]
    if missing or not isinstance(count, int) or isinstance(count, bool) or count < 0:
        return {'rule_id': rule_id, 'status': 'unmeasured',
                'reason': 'the measured claim is missing ' + ','.join(missing or ['false_positives'])}
    return {'rule_id': rule_id, 'status': 'measured', 'false_positives': count,
            'window': block['window'], 'population': block['population'],
            'measured_on': block['measured_on'], 'source': block['source']}


def measurement_report(artifacts: Any) -> dict[str, Any]:
    """Count the shipped rules and how many of them have ever been measured.

    ``N rules shipped, M unmeasured`` is the headline this repo gives a rule pack, because a rule set
    nobody has counted is how a pager becomes noise (notification budget) — so the honest number, not the count of
    rules, is the one an operator and corpus eval's gate read. `artifacts` is an iterable of already-loaded
    compiled artifacts or of paths to them (paths go through `artifact`, so a corrupted file is a
    refusal here and not a silently uncounted rule).

    Returns:
        ``{'shipped': int, 'measured': int, 'unmeasured': int, 'headline': str,
        'rules': [per-artifact verdict from `measurement_status`]}``, ordered by rule id so the same
        set of files always produces the same document. `measurement_signal` is the form of that
        document an operator surface can read.
    """
    rules = [measurement_status(item if isinstance(item, dict) else artifact(item))
             for item in artifacts]
    rules.sort(key=lambda rule: rule['rule_id'])
    unmeasured = sum(1 for rule in rules if rule['status'] == 'unmeasured')
    return {'shipped': len(rules), 'measured': len(rules) - unmeasured, 'unmeasured': unmeasured,
            'headline': f'{len(rules)} rules shipped, {unmeasured} unmeasured', 'rules': rules}


def measurement_signal(report: dict[str, Any], *, now: dt.datetime, source: str = MEASUREMENT_SOURCE,
                       max_age_seconds: int = MEASUREMENT_MAX_AGE_SECONDS) -> dict[str, Any]:
    """Put one `measurement_report` into the shape `/v1/overview` reads a `sigma` observation from.

    The format half of a pair with `platform/overview.py`, which validates that shape and refuses any
    other; the round trip is asserted in `tests/test_overview_sigma.py`, so the two sides cannot drift
    into a silently-empty tile. `status` is the pack's own account, not a health verdict: `healthy` means
    every shipped rule carries a measured false-positive count, `degraded` means at least one does not.
    Neither opens nor resolves anything — `state.py` decides what is open (incident and action state) and this signal
    only
    reports, which is why it is not the runner's healthcheck either.

    The caller is `platform/overview_worker.py` (overview sigma producer): when its configuration names a
    `sigma_artifacts`
    directory it publishes this signal beside `jobs` and `model`; with no such key every deployment reads
    `unknown` with three nulls. The bounds the reader imposes on its own document (headline length,
    provenance length, freshness ceiling) are left to it rather than restated here, so one file owns them.

    Raises:
        ValueError: when `report` is not the document `measurement_report` returns — a missing key, a
            count that is not a nonnegative integer, parts that do not sum to `shipped`, or a headline
            that is not a sentence.
    """
    missing = [key for key in (*MEASUREMENT_TRIPLE, 'headline') if key not in report]
    if missing:
        raise ValueError('measurement_signal requires ' + ','.join(missing))
    triple = {key: report[key] for key in MEASUREMENT_TRIPLE}
    if any(type(value) is not int or value < 0 for value in triple.values()):
        raise ValueError('Sigma measurement counts must be nonnegative integers')
    if triple['shipped'] != triple['measured'] + triple['unmeasured']:
        raise ValueError('Sigma measurement does not account for every shipped rule')
    headline = report['headline']
    if not isinstance(headline, str) or not headline.strip():
        raise ValueError('Sigma measurement requires a headline sentence')
    if not isinstance(source, str) or not source.strip():
        raise ValueError('Sigma measurement requires provenance')
    # The headline travels inside the value rather than being re-formatted by the reader: the sentence
    # "N rules shipped, M unmeasured" belongs to this module, and a second copy of that f-string in
    # `platform/overview.py` is a phrase that could drift away from the number beside it.
    return {'status': 'healthy' if triple['unmeasured'] == 0 else 'degraded',
            'value': {**triple, 'headline': headline.strip()}, 'observed_at': utc_text(now),
            'max_age_seconds': max_age_seconds, 'source': source.strip()}


def artifact(path: Path | str) -> dict[str, Any]:
    """Read and validate one compiled artifact, refusing it whole rather than partly believing it.

    The file is sized before it is opened, so a mounted file that is not a compiled rule is refused
    without being read into this process (map guard and artifact cap, the artifact size limit); a truncated read is
    never returned. What is
    checked after that is the artifact's own account of itself: the schema and mapping it claims, the
    UUID shape of its rule id, and the digest of the SQL against the digest recorded in the file.

    Raises:
        FileNotFoundError: the artifact is not there (kept from the read, not converted into a value
            refusal, because "not mounted" and "mounted and wrong" are different operator actions).
        ValueError: the file is larger than `ARTIFACT_MAX_BYTES`, the mapping or schema version is not
            the one this runner speaks, the rule id is not a UUID, the SQL digest does not match the
            artifact's own `sql_sha256`, or the query is longer than the bound `tick` may send.
    """
    source = Path(path)
    size = source.stat().st_size
    if size > ARTIFACT_MAX_BYTES:
        raise ValueError(f'Compiled artifact is {size} bytes, above the bound of '
                         f'{ARTIFACT_MAX_BYTES}: {source}')
    result = json.loads(source.read_text())
    if result['schema_version'] != 1 or result['mapping'] != 'signoz-logs-v2-linux-process-v1':
        raise ValueError('Unsupported compiled mapping')
    uuid.UUID(result['rule_id'])
    if hashlib.sha256(result['sql'].encode()).hexdigest() != result['sql_sha256']:
        raise ValueError('Compiled SQL checksum mismatch')
    if len(result['sql']) > 65536:
        raise ValueError('Compiled query exceeds bound')
    return result


def tick(index_path: Path | str, compiled: dict[str, Any], resource_id: str, cursor_path: Path | str,
         query_client: ClickHouse, platform: JsonClient, *, now: dt.datetime,
         source: str = 'sigma-stage', window_seconds: int = 60, security: Any = None) -> str:
    """Evaluate one window, deliver its events, and copy any finding to the analytical store.

    ``security`` is an optional `local_observe.security.dualwrite.SecuritySink`. It changes nothing
    about the operational path, which is the point: ``state.py`` decides what is open (incident and action state) and a
    refused analytical **copy** must never delay a finding or lose a batch. So the copy is attempted
    while the batch is composed (its verdict becomes a third event, see
    ``local_observe/security/dualwrite.py``), and re-attempted on a replay while the batch is still
    owed — where a replay re-sends the same ``(source, source_event_id)`` identity and the owned table
    keeps one row, which is the property `docs/CONTRACTS.md` §4 asks for.
    """
    if not 1 <= window_seconds <= 3600:
        raise ValueError('Invalid window')
    with index.readonly(index_path) as connection:
        if index.resolve(connection, resource_id=resource_id)['status'] != 'resolved':
            raise ValueError('Undeclared resource')
    path = Path(cursor_path)
    binding = digest([compiled, resource_id, source, window_seconds])
    state = json.loads(path.read_text()) if path.exists() else {'binding': binding, 'last_end': None, 'pending': None}
    if state.get('binding') != binding:
        raise ValueError('Cursor belongs to a different rule or target')
    end = dt.datetime.fromtimestamp(int(now.timestamp()) // window_seconds * window_seconds, dt.timezone.utc)
    if state['pending'] is None and state['last_end'] and state['last_end'] >= utc_text(end):
        return 'idle'
    if state['pending'] is None:
        start = end - dt.timedelta(seconds=window_seconds)
        window = {'start': utc_text(start), 'end': utc_text(end)}
        epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
        parameters = {'start_ns': int((start - epoch).total_seconds()) * 1000000000,
                      'end_ns': int((end - epoch).total_seconds()) * 1000000000,
                      'resource_id': resource_id, 'dataset': compiled['dataset']}
        counts = None
        try:
            row = query_client.query(compiled['sql'], parameters)
            counts = {key: int(row[key]) for key in ('source_count', 'usable_count', 'match_count')}
            if not 0 <= counts['match_count'] <= counts['usable_count'] <= counts['source_count'] <= 1000000:
                raise ValueError('Invalid aggregate counts')
        except (TransportError, ValueError, KeyError, TypeError):
            counts = None
        fresh = counts is not None and counts['source_count'] > 0 and counts['usable_count'] == counts['source_count']
        rule = 'sigma.' + compiled['rule_id']
        version = compiled['rule_sha256'][:16]
        evidence = {'rule_id': rule, 'artifact_sha256': compiled['sql_sha256']}
        sample = None
        if counts is not None:
            sample = {'sample_id': digest([binding, window, counts]), 'observed_at': window['end'],
                      'ok': fresh, 'value': counts['match_count']}
            evidence['sample_id'] = sample['sample_id']
        events = [event(source, resource_id, rule + '.coverage', 'coverage', 'resolved' if fresh else 'firing',
                        window, evidence, query_type='sigma-source-coverage', version=version)]
        if fresh:
            # event vocabulary gave Sigma findings a kind of their own. `threshold` describes a numeric limit and
            # named nothing about what had matched, which is exactly why a security kind is needed;
            # coverage stays `coverage` — a missing log source is not a security finding.
            events.append(event(source, resource_id, rule, 'security',
                                'firing' if counts['match_count'] else 'resolved',
                                window, evidence, query_type='sigma-count', version=version))
        state['pending'] = {'end': utc_text(end), 'events': events, 'counts': counts, 'sample': sample}
        if security is not None:
            verdict = security.record(events, now=now, artifact_sha256=compiled['sql_sha256'])
            state['pending']['store'] = verdict.store
            if verdict.report:
                # A third event, about the analytical store itself: `resolved` when the store took the
                # copy (or this window held no finding and the periodic TTL read agreed), `firing` when
                # it did not. Filed before delivery so the batch that carries a finding also carries
                # where its copy went — "nobody is watching" has to be a state somebody can see.
                events.append(event(source, resource_id, rule + '.store-coverage', 'coverage',
                                    'resolved' if verdict.healthy else 'firing', window,
                                    {'rule_id': rule}, query_type='source-heartbeat', version=version))
            if not verdict.healthy:
                log.warning('Sigma analytical copy refused', extra={'store': verdict.store,
                                                                   'ttl': verdict.ttl.status if verdict.ttl else None})
        save(path, state)
    elif security is not None and state['pending'].get('store') not in ('written', 'idle'):
        # The batch is still owed (an acknowledgement was lost) and its copy never landed: retry the
        # copy without waiting for the delivery, and without ever failing the delivery because of it.
        retry = security.record(state['pending']['events'], now=now, artifact_sha256=compiled['sql_sha256'])
        state['pending']['store'] = retry.store
        if not retry.healthy:
            log.warning('Sigma analytical copy still refused; exact batch retained',
                        extra={'store': retry.store})
        save(path, state)
    if state['pending']['sample']:
        if platform.request('POST', '/v1/evidence', state['pending']['sample'])[0] != 200:
            raise TransportError('Sigma evidence refused; exact batch retained')
    for item in state['pending']['events']:
        if platform.request('POST', '/v1/events', item)[0] != 200:
            raise TransportError('Sigma intake refused; exact batch retained')
    save(path, {'binding': binding, 'last_end': state['pending']['end'], 'pending': None})
    return 'delivered'


def security_sink(environ: Any = None) -> Any:
    """Build the analytical write hook from the environment, or return ``None`` when it is off.

    ``LO_SECURITY_CLICKHOUSE_URL`` is the switch, and it is a separate endpoint+credential pair from
    ``LO_CLICKHOUSE_*`` on purpose: the runner's existing user is ``readonly = 1`` with SELECT on the
    three signal databases and cannot insert anywhere (see
    ``components/data/store-signoz/clickhouse-users.d/CONTRACT.md``). Unset means no copy and no
    coverage events about a store nobody asked for — one INFO line, so a deployment is never silently
    missing this. Set but unusable is a startup failure, not a downgrade: ``read_credential`` raises,
    and a sink that quietly became ``None`` would turn a broken credential into an unreported gap.
    """
    import os
    from local_observe.security.dualwrite import SecuritySink
    from local_observe.security.store import (ClickHouseSecurityReader, ClickHouseSecurityWriter,
                                            SecurityEventStore)

    values = os.environ if environ is None else environ
    url = values.get('LO_SECURITY_CLICKHOUSE_URL')
    if not url:
        log.info('Analytical security store is not configured',
                 extra={'variable': 'LO_SECURITY_CLICKHOUSE_URL'})
        return None
    allow_http = values.get('LO_INTERNAL_ALLOW_HTTP') == '1'
    user = values.get('LO_SECURITY_CLICKHOUSE_USER') or 'lo-security'
    password = read_credential('LO_SECURITY_CLICKHOUSE_PASSWORD', environ=values)
    return SecuritySink(SecurityEventStore(
        writer=ClickHouseSecurityWriter(url, user, password, allow_http=allow_http),
        reader=ClickHouseSecurityReader(ClickHouse(url, user, password, allow_http=allow_http))))


def main() -> None:
    from local_observe.http import JsonClient
    compiled = artifact(os.environ['LO_SIGMA_ARTIFACT'])
    # The first thing this container says is how much of what it is watching has ever been counted.
    # It is one line at start rather than a per-window line: the answer is a property of the reviewed
    # artifact, and a health that repeats once per tick is noise that hides the ticks that mattered.
    summary = measurement_report([compiled])
    log.info('Sigma rule measurement', extra={'shipped': summary['shipped'], 'measured': summary['measured'],
                                             'unmeasured': summary['unmeasured'], 'headline': summary['headline']})
    cursor = Path(os.environ['LO_SIGMA_CURSOR'])
    cursor.parent.mkdir(parents=True, exist_ok=True)
    query = ClickHouse(os.environ['LO_CLICKHOUSE_URL'], os.environ['LO_CLICKHOUSE_USER'],
                       read_credential('LO_CLICKHOUSE_PASSWORD'),
                       allow_http=os.environ.get('LO_INTERNAL_ALLOW_HTTP') == '1')
    platform = JsonClient(os.environ['LO_PLATFORM_URL'], read_credential('LO_PRODUCER_TOKEN'),
                          allow_http=os.environ.get('LO_INTERNAL_ALLOW_HTTP') == '1')
    security = security_sink()
    with exclusive_owner(cursor):
        while True:
            try:
                result = tick(os.environ['LO_INDEX_PATH'], compiled, os.environ['LO_RESOURCE_ID'], cursor, query,
                              platform, now=dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=30),
                              source=os.environ.get('LO_SIGMA_SOURCE', 'sigma-stage'), security=security)
                log.info('Sigma tick finished', extra={'result': result, 'rule_id': compiled['rule_id']})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                log.warning('Sigma evaluation unavailable; pending batch retained',
                            extra={'error_class': type(exc).__name__})
                log.debug('Sigma tick failed', exc_info=True)
            time.sleep(2)


if __name__ == '__main__':
    main()

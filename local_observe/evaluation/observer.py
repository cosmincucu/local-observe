"""Run the production observer over held-out telemetry without giving it truth labels."""
import datetime as dt
from dataclasses import asdict
from pathlib import Path

from local_observe.inventory.validation import timestamp, utc_text

from .arms import finding
from .model import CorpusError
from .decisions import identity, signature
from .provenance import cycle_identity, digest, safe_provenance


class CorpusSources:
    def __init__(self, series, sources):
        indexed = {(row['resource_id'], row['metric']): row for row in series}
        self.series = {source.id: indexed[source.resource_id, source.metric_name] for source in sources}

    def read(self, source, window, now):
        row = self.series[source.id]
        start, end = timestamp(window['start']).timestamp(), timestamp(window['end']).timestamp()
        return {'schema_version': 1, 'source': source.id, 'query_type': source.query_type,
                'resource_id': source.resource_id, 'window': dict(window), 'observed_at': utc_text(now),
                'rows': [{'timestamp': utc_text(dt.datetime.fromtimestamp(point['ts'], dt.timezone.utc)),
                          'value': point['v'], 'labels': {'metric_name': row['metric']}}
                         for point in row['rows'] if start <= point['ts'] < end]}


class CurrentModel:
    """Historical telemetry must not rewind live credential/capability policy checks."""
    def __init__(self):
        from local_observe.observer.adapters import Model
        self.model = Model()

    @property
    def secrets(self):
        return self.model.secrets

    def complete(self, evidence, allowed, config, now):
        return self.model.complete(evidence, allowed, config, dt.datetime.now(dt.timezone.utc))

    def provenance(self):
        return self.model.provenance()


def judge(context, *, directory, model_factory=None, config=None):
    """One real observer per comparison run; durable cycles have no external sender.

    Only the caller's telemetry and evaluation range enter this function. Configured
    cycles use the same series as other arms, subject to production limits.
    A partial/failed cycle makes the comparison incomplete, even if it emitted findings.
    """
    if set(context) != {'series', 'evaluation'}:
        raise CorpusError('Observer context must not carry truth')
    from local_observe.observer.contract import Config, Source
    from local_observe.observer.journal import Journal
    from local_observe.observer.runtime import Observer
    if not 1 <= len(context['series']) <= 20:
        raise CorpusError('Observer comparison needs 1..20 configured series')
    sources = tuple(Source(id=f'series-{number}', query_type='metric-threshold',
                           resource_id=row['resource_id'], metric_name=row['metric'])
                    for number, row in enumerate(context['series']))
    configured = config is not None
    config = config or Config(sources=sources, max_sources=len(sources), max_rows=2000,
                              max_age_seconds=3600, data_class='internal', mode='recording')
    if not isinstance(config, Config):
        raise CorpusError('Observer configuration must be a validated Config')
    selected = [(source.resource_id, source.metric_name) for source in config.sources]
    available = {(row['resource_id'], row['metric']) for row in context['series']}
    if (any(source.query_type != 'metric-threshold' for source in config.sources)
            or len(set(selected)) != len(selected) or set(selected) != available):
        raise CorpusError('Corpus must match all configured metric sources exactly and unambiguously')
    config_sha256 = digest(asdict(config))
    begin, end = timestamp(context['evaluation']['start']), timestamp(context['evaluation']['end'])
    duration = (end - begin).total_seconds()
    if (duration < config.window_seconds or begin.timestamp() % config.cadence_seconds
            or (duration - config.window_seconds) % config.cadence_seconds):
        raise CorpusError('Observer comparison requires complete configured cadence/windows')
    model = (model_factory or CurrentModel)()
    journal = Journal(Path(directory))
    cycles, findings, seen, decisions = [], [], set(), {}
    try:
        current = begin + dt.timedelta(seconds=config.window_seconds)
        while current <= end:
            cycle = Observer(config, journal, sources=CorpusSources(context['series'], config.sources), model=model,
                             clock=lambda at=current: at).run('evaluation-' + str(int(current.timestamp())))
            answer = cycle.get('answer') or {}
            structured = answer.get('findings', [])
            supported = not (cycle.get('decision') == 'tell' and not structured)
            cycles.append({'cycle_id': cycle['cycle_id'], 'status': cycle['status'],
                           'coverage': cycle['coverage'], 'decision': cycle['decision'],
                           'error': cycle['error'], 'structured_findings': supported,
                           'config_sha256': cycle.get('config_sha256'),
                           'provenance': safe_provenance(cycle.get('provenance')),
                           'model_calls': [{key: call.get(key) for key in
                                            ('status', 'model', 'response_model', 'usage', 'cost', 'elapsed_seconds')}
                                           | {'provenance': safe_provenance(call.get('provenance'))}
                                           for call in cycle['model_calls']]})
            window = {'start': utc_text(current - dt.timedelta(seconds=config.window_seconds)),
                      'end': utc_text(current)}
            for resource in sorted({source.resource_id for source in config.sources}):
                decisions[identity(resource, window)] = (signature(cycle['decision'],
                    [item['kind'] for item in structured if item['resource_id'] == resource])
                    if cycle['status'] == 'completed' and cycle['coverage'] == 'complete' and supported else None)
            for item in structured:
                key = item['resource_id'], item['kind'], int(current.timestamp())
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding(item['resource_id'], item['kind'],
                                        timestamp(item['observed_at']).timestamp(), arm='llm-rca', window=window))
            current += dt.timedelta(seconds=config.cadence_seconds)
    finally:
        journal.close()
    complete = bool(cycles) and all(row['status'] == 'completed' and row['coverage'] == 'complete'
                   and row['structured_findings'] for row in cycles)
    # Repeatability compares outcomes, never latency, token usage or fresh record IDs.
    verdicts = [{key: row[key] for key in ('status', 'coverage', 'decision', 'error', 'structured_findings')}
                for row in cycles]
    provenance = cycle_identity(cycles, config_sha256)
    return {'status': 'measured' if complete and provenance else 'unjudgeable', 'findings': findings,
            'cycles': cycles, 'verdicts': verdicts, 'decisions': decisions, 'coverage_complete': complete,
            'config_sha256': config_sha256, 'provenance': provenance,
            'configuration_authority': 'operator-supplied' if configured else 'demo-default',
            'filing_cadence_seconds': config.cadence_seconds,
            'input_scope': 'shared corpus; configured observation window and cadence',
            'external_notifications': False}

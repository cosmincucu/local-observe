"""Run the production observer over held-out telemetry without giving it truth labels."""
import datetime as dt
from pathlib import Path

from local_observe.inventory.validation import timestamp, utc_text

from .arms import finding
from .model import CorpusError


class CorpusSources:
    def __init__(self, series):
        self.series = {f'series-{index}': row for index, row in enumerate(series)}

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


def judge(context, *, directory, model_factory=None):
    """One real observer per comparison run; durable cycles have no external sender.

    Only the caller's telemetry and evaluation range enter this function. Each fixed
    hourly cycle uses the same series as other arms, subject to production limits.
    A partial/failed cycle makes the comparison incomplete, even if it emitted findings.
    """
    if set(context) != {'series', 'evaluation'}:
        raise CorpusError('Observer context must not carry truth')
    from local_observe.observer.contract import Config, Source
    from local_observe.observer.journal import Journal
    from local_observe.observer.runtime import Observer
    if not 1 <= len(context['series']) <= 20:
        return {'status': 'unjudgeable', 'findings': [], 'reason': 'observer_source_limit'}
    sources = tuple(Source(id=f'series-{number}', query_type='metric-threshold',
                           resource_id=row['resource_id'], metric_name=row['metric'])
                    for number, row in enumerate(context['series']))
    config = Config(sources=sources, max_sources=len(sources), max_rows=2000,
                    max_age_seconds=3600, data_class='internal', mode='recording')
    begin, end = timestamp(context['evaluation']['start']), timestamp(context['evaluation']['end'])
    if begin.minute or begin.second or begin.microsecond or (end - begin).total_seconds() % 3600:
        raise CorpusError('Observer comparison requires complete fixed hourly windows')
    model = (model_factory or CurrentModel)()
    journal = Journal(Path(directory))
    cycles, findings, seen = [], [], set()
    try:
        current = begin + dt.timedelta(hours=1)
        while current <= end:
            cycle = Observer(config, journal, sources=CorpusSources(context['series']), model=model,
                             clock=lambda at=current: at).run('evaluation-' + str(int(current.timestamp())))
            answer = cycle.get('answer') or {}
            structured = answer.get('findings', [])
            supported = not (cycle.get('decision') == 'tell' and not structured)
            cycles.append({'cycle_id': cycle['cycle_id'], 'status': cycle['status'],
                           'coverage': cycle['coverage'], 'decision': cycle['decision'],
                           'error': cycle['error'], 'structured_findings': supported,
                           'model_calls': [{key: call.get(key) for key in
                                            ('status', 'model', 'response_model', 'usage', 'cost', 'elapsed_seconds')}
                                           for call in cycle['model_calls']]})
            for item in structured:
                key = item['resource_id'], item['kind'], int(current.timestamp()) // 3600
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding(item['resource_id'], item['kind'],
                                        timestamp(item['observed_at']).timestamp(), arm='llm-rca'))
            current += dt.timedelta(hours=1)
    finally:
        journal.close()
    complete = all(row['status'] == 'completed' and row['coverage'] == 'complete'
                   and row['structured_findings'] for row in cycles)
    # Repeatability compares outcomes, never latency, token usage or fresh record IDs.
    verdicts = [{key: row[key] for key in ('status', 'coverage', 'decision', 'error', 'structured_findings')}
                for row in cycles]
    return {'status': 'measured' if complete else 'unjudgeable', 'findings': findings,
            'cycles': cycles, 'verdicts': verdicts, 'filing_cadence_seconds': 3600,
            'input_scope': 'shared corpus; observer reads one fixed hour per cycle',
            'external_notifications': False}

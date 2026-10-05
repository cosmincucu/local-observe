"""Run the production observer over held-out telemetry without giving it truth labels."""
import datetime as dt
from dataclasses import asdict
from pathlib import Path

from local_observe.inventory.validation import canonical, timestamp, utc_text

from .arms import finding
from .model import CorpusError
from .decisions import identity
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


def match_sources(series, sources):
    """Refuse unless every configured metric source maps to exactly one corpus series.

    Shared by the comparison run and the model-free preflight so their source mappings agree.
    """
    selected = [(source.resource_id, source.metric_name) for source in sources]
    available = {(row['resource_id'], row['metric']) for row in series}
    if (any(source.query_type != 'metric-threshold' for source in sources)
            or len(set(selected)) != len(selected) or set(selected) != available):
        raise CorpusError('Corpus must match all configured metric sources exactly and unambiguously')


def cycle_windows(evaluation, config):
    """Return every complete aligned observation window a comparison must cover."""
    begin, end = timestamp(evaluation['start']), timestamp(evaluation['end'])
    duration = (end - begin).total_seconds()
    if (duration < config.window_seconds or begin.timestamp() % config.cadence_seconds
            or (duration - config.window_seconds) % config.cadence_seconds):
        raise CorpusError('Observer comparison requires complete configured cadence/windows')
    windows, current = [], begin + dt.timedelta(seconds=config.window_seconds)
    while current <= end:
        windows.append({'start': utc_text(current - dt.timedelta(seconds=config.window_seconds)),
                        'end': utc_text(current)})
        current += dt.timedelta(seconds=config.cadence_seconds)
    return windows


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

    def provenance_for_route(self, receipt):
        return self.model.provenance_for_route(receipt)


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
    match_sources(context['series'], config.sources)
    config_sha256 = digest(asdict(config))
    windows = cycle_windows(context['evaluation'], config)
    model = (model_factory or CurrentModel)()
    journal = Journal(Path(directory))
    cycles, findings, decisions, resource_findings = [], [], {}, {}
    try:
        for window in windows:
            current = timestamp(window['end'])
            cycle = Observer(config, journal, sources=CorpusSources(context['series'], config.sources), model=model,
                             clock=lambda at=current: at).run('evaluation-' + str(int(current.timestamp())))
            answer = cycle.get('answer') or {}
            structured = answer.get('findings', [])
            supported = not (cycle.get('decision') == 'tell' and not structured)
            covered = {row['source'] for row in cycle.get('evidence', []) if row.get('coverage') == 'complete'}
            evaluation_complete = {source.id for source in config.sources} <= covered
            known = (cycle['status'] == 'completed' and cycle['coverage'] == 'complete'
                     and cycle.get('decision') in ('quiet', 'watch', 'tell') and cycle.get('error') is None
                     and supported and evaluation_complete)
            cycles.append({'cycle_id': cycle['cycle_id'], 'status': cycle['status'],
                           'coverage': cycle['coverage'], 'decision': cycle['decision'],
                           'error': cycle['error'], 'structured_findings': supported,
                           'evaluation_complete': evaluation_complete,
                           'window': window, 'covered_sources': sorted(covered),
                           'config_sha256': cycle.get('config_sha256'),
                           'provenance': safe_provenance(cycle.get('provenance')),
                           'model_calls': [{key: call.get(key) for key in
                                            ('status', 'model', 'response_model', 'usage', 'cost', 'elapsed_seconds')}
                                           | {'provenance': safe_provenance(call.get('provenance'))}
                                           | ({'model_route': call['model_route']} if 'model_route' in call else {})
                                           for call in cycle['model_calls']]})
            for resource in sorted({source.resource_id for source in config.sources}):
                kinds = [item['kind'] for item in structured if item['resource_id'] == resource]
                read = {source.id for source in config.sources if source.resource_id == resource} <= covered
                resource_findings[identity(resource, window)] = (
                    {'kinds': sorted(kinds)} if read and cycle['status'] == 'completed'
                    and cycle['coverage'] == 'complete' and cycle.get('error') is None and supported else None)
            # The investigator emits one cycle-wide verdict. Do not copy it onto resources or
            # enlarge its denominator with sources that were never investigated.
            decisions[canonical({'window': window})] = (canonical({'decision': cycle['decision'],
                'findings': sorted({(item['resource_id'], item['kind']) for item in structured})}) if known else None)
            for item in structured:
                findings.append(finding(item['resource_id'], item['kind'],
                    timestamp(item['observed_at']).timestamp(), arm='llm-rca', window=window,
                    observation=sorted(item['evidence_ids'])))
    finally:
        journal.close()
    complete = bool(cycles) and all(value is not None for value in decisions.values())
    # Repeatability compares outcomes, never latency, token usage or fresh record IDs.
    verdicts = [{key: row[key] for key in ('status', 'coverage', 'decision', 'error', 'structured_findings')}
                for row in cycles]
    provenance = cycle_identity(cycles, config_sha256)
    return {'status': 'measured' if complete and provenance else 'unjudgeable', 'findings': findings,
            'cycles': cycles, 'verdicts': verdicts, 'decisions': decisions, 'coverage_complete': complete,
            'decision_unit': 'cycle-window', 'resource_findings': resource_findings,
            'config_sha256': config_sha256, 'provenance': provenance,
            'configuration_authority': 'operator-supplied' if configured else 'demo-default',
            'filing_cadence_seconds': config.cadence_seconds,
            'input_scope': 'shared corpus; configured observation window and cadence',
            'external_notifications': False}

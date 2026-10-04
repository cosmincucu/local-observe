"""Check necessary observer input conditions without journals, credentials or model calls."""
import re
from collections import Counter
import datetime as dt
from dataclasses import asdict

from local_observe.inventory.validation import canonical, timestamp
from local_observe.observer.contract import Config, ObserverError, encoded, snapshot, utc

from .baseline_config import prepare, validate_config
from .manifest import sha
from .model import CorpusError, validate
from .observer import CorpusSources, cycle_windows, match_sources
from .provenance import digest

REVISION = re.compile('[0-9a-f]{40}')
# Bound local work too; split larger studies into independently evaluated windows.
MAX_SOURCE_READS = 4000
NOT_CHECKED = ('Observer provenance, credentials, gateway reachability and live model capability',
               'Whether corpus, truth and retrieval records stay disjoint over time',
               'Whether the model answers, requests follow-ups, or meets any quality floor',
               'Sample arrival delay at run time; only corpus-bounded staleness is measured here',
               'Baseline history sufficiency, detector behavior and model latency within the cycle deadline',
               'Notification policy, delivery approval and human review burden')


def follow_up_capacity(config):
    """Non-initial sources are read only if a model asks for them, so they are never guaranteed."""
    initial = sum(1 for source in config.sources if source.initial)
    pending = len(config.sources) - initial
    # Production needs one call to request the follow-up and a second to answer with its evidence,
    # and enough source slots to cover every pending source in the comparison.
    required = 2 if pending else 1
    capacity = 'not_required'
    if pending:
        capacity = ('insufficient' if config.max_model_calls < required or len(config.sources) > config.max_sources
                    else 'conditional')
    return {'sources': pending, 'model_calls': config.max_model_calls, 'required_model_calls': required,
            'capacity': capacity}


def union_seconds(windows):
    """Measure half-open intervals without double-counting overlapping or touching windows."""
    intervals = sorted((timestamp(row['start']).timestamp(), timestamp(row['end']).timestamp())
                       for row in windows)
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return sum(end - start for start, end in merged)


def label_coverage(corpus):
    """Quiet windows cover every resource; labelled windows cover only their named resource.

    Incidents label a positive class, never exhaustive negatives. Resource indices follow
    first appearance in corpus series and keep private identities out of diagnostics.
    """
    resources = list(dict.fromkeys(row['resource_id'] for row in corpus['series']))
    duration = (timestamp(corpus['evaluation']['end'])
                - timestamp(corpus['evaluation']['start'])).total_seconds()
    coverage = []
    for index, resource in enumerate(resources):
        covered = union_seconds(corpus['quiet'] + [row['window'] for row in corpus['labelled']
                                                   if row['resource_id'] == resource])
        coverage.append({'resource_index': index, 'exhaustive_seconds': covered,
                         'unknown_seconds': max(0.0, duration - covered)})
    return {'unit': 'resource_seconds', 'window_seconds': duration,
            'duration_seconds': duration * len(resources),
            'exhaustive_seconds': sum(row['exhaustive_seconds'] for row in coverage),
            'unknown_seconds': sum(row['unknown_seconds'] for row in coverage),
            'resources': coverage, 'quiet_windows': len(corpus['quiet']),
            'labelled_windows': len(corpus['labelled']),
            'labelled_resources': len({row['resource_id'] for row in corpus['labelled']} & set(resources)),
            'out_of_scope_labelled_windows': sum(row['resource_id'] not in resources for row in corpus['labelled']),
            'incident_labels': len(corpus['incidents']), 'incidents_are_exhaustive_negatives': False}


def preflight(corpus, *, revision, observer_config, baseline_config):
    """Return payload-free diagnostics for one corpus, Config and detector baseline."""
    corpus = validate(corpus)
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        raise CorpusError('Revision must be a complete lowercase Git commit id')
    if not isinstance(observer_config, Config):
        raise CorpusError('Observer configuration must be a validated Config')
    if baseline_config is None:
        raise CorpusError('Preflight requires an explicit baseline configuration')
    _, _, detector = prepare(corpus, validate_config(baseline_config))
    match_sources(corpus['series'], observer_config.sources)
    windows = cycle_windows(corpus['evaluation'], observer_config)
    initial = [source for source in observer_config.sources if source.initial]
    if not initial:
        raise CorpusError('Preflight requires at least one initial source')
    if len(windows) * len(observer_config.sources) > MAX_SOURCE_READS:
        raise CorpusError('Preflight source-read bound exceeded; split the study into smaller windows')
    gaps, incomplete = [], set()

    def add(code, window_index=None, source_index=None):
        gaps.append({'code': code, 'window_index': window_index, 'source_index': source_index})
        if window_index is not None:
            incomplete.add(window_index)

    if observer_config.max_model_calls < 1:
        add('model_budget_exhausted')
    capacity = follow_up_capacity(observer_config)
    if capacity['capacity'] == 'insufficient':
        add('follow_up_capacity_insufficient')
    if len(initial) > observer_config.max_sources:
        add('initial_sources_exceed_max_sources')
    elif len(observer_config.sources) > observer_config.max_sources:
        add('configured_sources_exceed_max_sources')
    if gaps:
        incomplete.update(range(len(windows)))
    reader = CorpusSources(corpus['series'], observer_config.sources)
    peak_bytes = usable_cycles = planned_reads = 0
    for index, aligned in enumerate(windows):
        # Frame each window exactly as a production cycle does, so byte accounting is comparable.
        end = timestamp(aligned['end'])
        window = {'start': utc(end - dt.timedelta(seconds=observer_config.window_seconds)), 'end': utc(end)}
        now = end
        evidence, usable = [], False
        # Full comparison coverage requires every configured source, including follow-ups.
        # Initial reads precede conditional reads, as in production; the model may still
        # choose not to request the latter. Capacity failures do not suppress diagnostics.
        ordered = sorted(enumerate(observer_config.sources), key=lambda pair: not pair[1].initial)
        for position, source in ordered:
            planned_reads += 1
            try:
                item = snapshot(source, reader.read(source, window, now), window, observer_config, now)
                total = len(encoded([*evidence, item]).encode())
                if total > observer_config.max_result_bytes:
                    raise ObserverError('cycle_evidence_budget')
            except Exception as exc:
                # Same vocabulary as the runtime: only a public code survives, never exception prose.
                add(str(exc) if isinstance(exc, ObserverError) else 'source_unavailable', index, position)
                continue
            evidence.append(item)
            peak_bytes = max(peak_bytes, total)
            if item['rows'] and source.initial:
                usable = True
            if not item['rows']:
                add('empty_sample', index, position)
        if not usable:
            add('no_usable_evidence', index)
        else:
            usable_cycles += 1
    caveats = []
    if capacity['capacity'] == 'conditional':
        caveats.append('conditional_sources_require_model_follow_up')
    if observer_config.retrieval_examples:
        caveats.append('retrieved_history_bytes_are_not_modelled')
    labels = label_coverage(corpus)
    if labels['unknown_seconds']:
        caveats.append('unknown_label_intervals')
    counts = dict(Counter(gap['code'] for gap in gaps))
    return {'schema_version': 1, 'revision': revision,
            'binding': {'corpus_sha256': sha(canonical(corpus).encode('utf-8')),
                        'config_sha256': digest(asdict(observer_config)),
                        'baseline_sha256': detector['config_sha256'],
                        'inventory_sha256': detector['inventory_sha256']},
            'configuration': {'sources': len(observer_config.sources), 'initial_sources': len(initial),
                              'cadence_seconds': observer_config.cadence_seconds,
                              'window_seconds': observer_config.window_seconds,
                              'max_sources': observer_config.max_sources,
                              'max_model_calls': observer_config.max_model_calls,
                              'max_rows': observer_config.max_rows,
                              'max_age_seconds': observer_config.max_age_seconds,
                              'max_result_bytes': observer_config.max_result_bytes},
            'cycles': {'count': len(windows), 'inputs_ready': len(windows) - len(incomplete),
                       'inputs_incomplete': len(incomplete), 'usable_initial_evidence': usable_cycles,
                       'source_reads': planned_reads, 'peak_evidence_bytes': peak_bytes,
                       'model_calls_required_per_run': len(windows) * capacity['required_model_calls']},
            'follow_up': capacity, 'labels': labels,
            'gaps': gaps, 'counts': counts, 'caveats': caveats,
            'inputs_feasible': not gaps,
            'not_checked': list(NOT_CHECKED),
            'authorizes_delivery': False, 'substitute_for_quality_report': False,
            'model_calls_made': 0, 'namespaces_reserved': 0}

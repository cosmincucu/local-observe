"""Protected local human acceptance. A measured report alone never grants delivery."""
from __future__ import annotations

import datetime as dt
import hashlib
import math
import os
from dataclasses import asdict
from pathlib import Path

from .contract import digest, encoded, fields, instant, require, strict_json, utc
from .environment import protected_bytes
from .provenance import build_provenance, is_digest, validate_provenance


def channel_identity(config) -> dict:
    return {'channel': 'telegram', 'chat_id': config.chat_id, 'user_id': config.user_id,
            'daily_limit': config.daily_limit, 'channel_sha256': digest(asdict(config))}


def _score(value, *, observer=False):
    require(isinstance(value, dict), 'quality_score_missing')
    counts = ('true_positives', 'false_positives', 'false_negatives', 'duplicates', 'non_firing',
              'findings', 'unlabelled_findings', 'total_findings')
    fields(value, {*counts, 'precision', 'recall', 'findings_per_day', 'matched', 'verdict'})
    require(value['verdict'] in ('measured', 'pass'), 'quality_score_unmeasured')
    require(all(type(value.get(k)) is int and 0 <= value[k] <= 1000000000 for k in counts), 'quality_counts_unknown')
    tp, fp, unknown = (value[k] for k in ('true_positives', 'false_positives', 'unlabelled_findings'))
    require(value['findings'] == tp + fp and value['total_findings'] == tp + fp + unknown,
            'quality_counts_inconsistent')
    require(unknown == 0, 'quality_unlabelled_findings')
    expected = tp / (tp + fp) if tp + fp else None
    require(value.get('precision') == expected and not isinstance(value.get('precision'), bool),
            'quality_precision_inconsistent')
    recall = tp / (tp + value['false_negatives']) if tp + value['false_negatives'] else None
    require(value['recall'] == recall and not isinstance(value['recall'], bool), 'quality_recall_inconsistent')
    matched = value.get('matched')
    require(isinstance(matched, list) and all(isinstance(x, str) for x in matched)
            and len(set(matched)) == len(matched) == tp, 'quality_matches_inconsistent')
    rate = value.get('findings_per_day')
    require(type(rate) in (int, float) and math.isfinite(rate) and rate >= 0, 'quality_rate_unknown')
    require((value['total_findings'] == 0) == (rate == 0), 'quality_rate_inconsistent')
    if observer:
        require(expected is not None and expected >= .7 and rate <= 2, 'quality_floor_failed')


def validate_report(report: dict, *, config_sha256: str, provenance: dict) -> dict:
    """Validate measured inputs as well as the verdict; missing measurements are not zero."""
    validate_provenance(provenance, require_complete=True)
    require(isinstance(report, dict) and type(report.get('schema_version')) is int
            and report['schema_version'] == 2, 'unsupported_quality_report')
    quality, manifest, runs = report.get('quality'), report.get('manifest'), report.get('runs')
    require(isinstance(quality, dict) and type(quality.get('schema_version')) is int
            and quality['schema_version'] == 2 and quality.get('verdict') == 'measured-pass'
            and quality.get('authorizes_delivery') is False and quality.get('reasons') == [],
            'quality_not_measured_pass')
    require(isinstance(manifest, dict) and type(manifest.get('schema_version')) is int
            and manifest['schema_version'] == 2 and manifest.get('origin') == quality.get('corpus_origin')
            == 'anonymized-example' and is_digest(manifest.get('corpus_sha256')), 'independent_corpus_required')
    require(type(quality.get('truth_incidents')) is int and quality['truth_incidents'] > 0, 'quality_truth_unknown')
    novel = quality.get('novel_classes')
    require(isinstance(novel, list) and 1 <= len(novel) <= 6
            and all(k in ('availability', 'coverage', 'threshold', 'drift', 'anomaly', 'security') for k in novel)
            and len(set(novel)) == len(novel),
            'quality_novelty_unknown')
    flip = quality.get('observer_flip_rate')
    require(type(flip) in (int, float) and math.isfinite(flip) and 0 <= flip < .1, 'quality_flip_unknown')
    require(isinstance(runs, list) and len(runs) == 3, 'quality_requires_three_runs')
    require(provenance['config_sha256'] == config_sha256, 'quality_configuration_changed')
    observer_manifest = manifest.get('observer')
    fields(observer_manifest, {'schema_version', 'config_sha256', 'configuration_authority', 'provenance'})
    require(type(observer_manifest['schema_version']) is int and observer_manifest['schema_version'] == 1
            and observer_manifest['configuration_authority'] == 'operator-supplied'
            and observer_manifest['config_sha256'] == config_sha256, 'quality_operator_configuration_required')
    require(validate_provenance(observer_manifest['provenance'], require_complete=True) == provenance,
            'quality_provenance_changed')
    flips = report.get('flip_rate')
    require(isinstance(flips, dict) and type(flips.get('runs')) is int and flips['runs'] == 3
            and isinstance(flips.get('measurements'), dict) and isinstance(flips.get('per_arm'), dict),
            'quality_flip_measurements_missing')
    for arm in ('static-threshold', 'seasonal', 'llm-rca'):
        measurement = flips['measurements'].get(arm)
        require(isinstance(measurement, dict) and measurement.get('status') == 'measured', 'quality_flip_incomplete')
        require(type(measurement.get('units')) is int and measurement['units'] > 0
                and type(measurement.get('missing_decisions')) is int and measurement['missing_decisions'] == 0
                and type(measurement.get('comparisons')) is int
                and measurement['comparisons'] == 3 * measurement['units']
                and type(measurement.get('disagreements')) is int
                and 0 <= measurement['disagreements'] <= 2 * measurement['units'], 'quality_flip_inconsistent')
        rate = measurement['disagreements'] / measurement['comparisons']
        require(type(flips['per_arm'].get(arm)) in (int, float) and flips['per_arm'][arm] == rate,
                'quality_flip_inconsistent')
        if arm == 'llm-rca':
            require(rate == flip, 'quality_flip_inconsistent')
    for run in runs:
        require(isinstance(run, dict), 'quality_run_invalid')
        for arm in ('static-threshold', 'seasonal', 'llm-rca'):
            measured = run.get(arm)
            require(isinstance(measured, dict) and measured.get('execution') == 'measured', 'quality_arm_incomplete')
            _score(measured.get('score'), observer=arm == 'llm-rca')
            detail = measured.get('detail')
            require(isinstance(detail, dict) and detail.get('coverage_complete') is True, 'quality_detail_missing')
            score = measured['score']
            require(score['true_positives'] + score['false_negatives'] == quality['truth_incidents'],
                    'quality_truth_inconsistent')
            if arm != 'llm-rca':
                require(all(type(detail.get(k)) is int and detail[k] == 0
                            for k in ('unjudgeable_points', 'unconfigured_series')), 'quality_baseline_incomplete')
                continue
            require(detail.get('config_sha256') == config_sha256
                    and detail.get('configuration_authority') == 'operator-supplied',
                    'quality_operator_configuration_required')
            require(validate_provenance(detail.get('provenance'), require_complete=True) == provenance,
                    'quality_provenance_changed')
            cycles = detail.get('cycles')
            require(isinstance(cycles, list) and bool(cycles), 'quality_cycles_missing')
            for cycle in cycles:
                require(isinstance(cycle, dict) and cycle.get('status') == 'completed'
                        and cycle.get('coverage') == 'complete' and cycle.get('error') is None
                        and cycle.get('structured_findings') is True, 'quality_cycle_incomplete')
                require(cycle.get('config_sha256') == config_sha256, 'quality_configuration_changed')
                require(validate_provenance(cycle.get('provenance'), require_complete=True) == provenance,
                        'quality_provenance_changed')
                calls = cycle.get('model_calls')
                require(isinstance(calls, list) and bool(calls), 'quality_model_unmeasured')
                for call in calls:
                    require(isinstance(call, dict) and call.get('status') == 'completed'
                            and call.get('model') == provenance['configured_model']
                            and call.get('response_model') == provenance['response_model'], 'quality_model_unmeasured')
                    require(validate_provenance(call.get('provenance'), require_complete=True) == provenance,
                            'quality_provenance_changed')
    return report


def _write(journal, output, value):
    fd = journal.create_file(output)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(encoded(value) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(journal.directory_fd)


def accept_quality(journal, *, report_path, config, model, channel, output, expires_at: str,
                   independent_held_out_labels: bool, now: dt.datetime) -> dict:
    require(independent_held_out_labels is True, 'independent_held_out_attestation_required')
    expiry = instant(expires_at)
    require(now < expiry <= now + dt.timedelta(days=30), 'invalid_acceptance_expiry')
    raw = protected_bytes(report_path, 4 * 1024 * 1024)
    report = strict_json(raw, 4 * 1024 * 1024, max_depth=20)
    # This location is fixed by the report integration contract; malformed input yields a bounded refusal.
    try:
        observed = report['runs'][0]['llm-rca']['detail']['cycles'][0]['provenance']
    except (KeyError, IndexError, TypeError) as exc:
        from .contract import ObserverError
        raise ObserverError('quality_provenance_missing') from exc
    validate_provenance(observed, require_complete=True)
    expected = build_provenance(config, model, response_model=observed['response_model'])
    validate_report(report, config_sha256=digest(asdict(config)), provenance=expected)
    receipt = {'schema_version': 1, 'report_sha256': hashlib.sha256(raw).hexdigest(),
               'config_sha256': digest(asdict(config)), 'provenance': expected,
               'actor': f'os-uid:{os.getuid()}', 'accepted_at': utc(now), 'expires_at': utc(expiry),
               'independent_held_out_labels': True, 'channel': channel_identity(channel)}
    receipt['sha256'] = digest(receipt)
    _write(journal, output, receipt)
    return receipt


class AcceptedQuality:
    """Re-read protected acceptance and original report at every dispatch; no cached authority."""

    def __init__(self, acceptance_path, report_path, *, journal, config, model, channel):
        self.acceptance_path, self.report_path = acceptance_path, report_path
        self.config, self.model, self.channel = config, model, channel
        self.journal = journal
        with journal.db:
            journal.db.execute('CREATE TABLE IF NOT EXISTS observer_revocations '
                               '(acceptance_sha256 TEXT PRIMARY KEY, actor TEXT NOT NULL, revoked_at TEXT NOT NULL)')

    def verify(self, now: dt.datetime) -> dict:
        receipt = strict_json(protected_bytes(self.acceptance_path), max_depth=20)
        fields(receipt, {'schema_version', 'report_sha256', 'config_sha256', 'provenance', 'actor', 'accepted_at',
                         'expires_at', 'independent_held_out_labels', 'channel', 'sha256'})
        require(type(receipt['schema_version']) is int and receipt['schema_version'] == 1, 'unsupported_acceptance')
        require(receipt['sha256'] == digest({k: v for k, v in receipt.items() if k != 'sha256'}),
                'acceptance_integrity_failed')
        require(receipt['actor'] == f'os-uid:{os.getuid()}' and receipt['independent_held_out_labels'] is True,
                'independent_held_out_attestation_required')
        require(self.journal.db.execute('SELECT 1 FROM observer_revocations WHERE acceptance_sha256=?',
                                        (receipt['sha256'],)).fetchone() is None, 'acceptance_revoked')
        accepted, expiry = instant(receipt['accepted_at']), instant(receipt['expires_at'])
        require(accepted <= now < expiry <= accepted + dt.timedelta(days=30), 'acceptance_expired')
        require(receipt['config_sha256'] == digest(asdict(self.config))
                and receipt['channel'] == channel_identity(self.channel), 'acceptance_binding_changed')
        observed = validate_provenance(receipt['provenance'], require_complete=True)
        expected = build_provenance(self.config, self.model, response_model=observed['response_model'])
        require(expected == observed, 'acceptance_provenance_changed')
        raw = protected_bytes(self.report_path, 4 * 1024 * 1024)
        require(hashlib.sha256(raw).hexdigest() == receipt['report_sha256'], 'accepted_report_changed')
        validate_report(strict_json(raw, 4 * 1024 * 1024, max_depth=20),
                        config_sha256=receipt['config_sha256'], provenance=expected)
        return receipt

    def revoke(self, *, now):
        receipt = strict_json(protected_bytes(self.acceptance_path), max_depth=20)
        require(is_digest(receipt.get('sha256')), 'invalid_acceptance')
        with self.journal.db:
            self.journal.db.execute('INSERT OR IGNORE INTO observer_revocations VALUES(?,?,?)',
                                    (receipt['sha256'], f'os-uid:{os.getuid()}', utc(now)))
        return {'acceptance_sha256': receipt['sha256'], 'revoked': True}

    def reviewed_precision(self, receipt) -> dict:
        """Human labels on delivered post-acceptance cycles; unknown is never a correct vote."""
        exists = self.journal.db.execute("SELECT 1 FROM sqlite_master WHERE name='observer_deliveries'").fetchone()
        known = correct = unknown = 0
        if exists:
            rows = self.journal.db.execute('''
                SELECT d.document,c.document,f.document FROM observer_deliveries d
                JOIN cycles c USING(cycle_id) LEFT JOIN feedback f ON f.cycle_id=d.cycle_id
                AND f.rowid=(SELECT max(f2.rowid) FROM feedback f2 WHERE f2.cycle_id=d.cycle_id)
                WHERE d.status='sent' AND d.day>=? ORDER BY d.rowid DESC LIMIT 1000
            ''', (instant(receipt['accepted_at']).date().isoformat(),))
            for delivery_raw, cycle_raw, feedback_raw in rows:
                delivery = strict_json(delivery_raw)
                cycle = strict_json(cycle_raw, 524288, max_depth=20)
                if (instant(delivery['attempted_at']) < instant(receipt['accepted_at'])
                        or cycle.get('provenance') != receipt['provenance']):
                    continue
                feedback = strict_json(feedback_raw) if feedback_raw else {}
                verdict = feedback.get('correctness')
                if verdict in ('correct', 'incorrect'):
                    known += 1
                    correct += verdict == 'correct'
                else:
                    unknown += 1
        return {'known': known, 'correct': correct, 'unknown': unknown,
                'precision': correct / known if known else None,
                'basis': 'latest_independent_human_correctness_after_acceptance'}

    def __call__(self, cycle, binding, now) -> bool:
        receipt = self.verify(now)
        observed = self.reviewed_precision(receipt)
        require(observed['precision'] is None or observed['precision'] >= .7, 'reviewed_precision_below_floor')
        require(validate_provenance(cycle.get('provenance'), require_complete=True) == receipt['provenance'],
                'delivery_provenance_changed')
        require(binding['channel_sha256'] == receipt['channel']['channel_sha256']
                and binding['daily_limit'] == receipt['channel']['daily_limit'], 'delivery_channel_changed')
        return True

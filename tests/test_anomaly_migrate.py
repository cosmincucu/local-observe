"""The anomaly cursor migration: the offline schema-1 → schema-2 anomaly cursor migration, and what it must not touch.

Every expectation here is read off the *producer*, not off the migration: the owed bytes come from real
rounds against the real `state.Store`, the platform HTTP boundary is the `Intake` stub that records the
canonical bytes it was handed, and the migrated file is accepted back by a real round that is then
required to POST those same bytes again. Testing the pure function against itself would only prove the
two halves of one idea agree, so it is not how the important cases here are checked.

The fixture base is the producer's own durability fixture (`test_anomaly.DurabilityFixture`), so a
"schema-1 cursor" in this file is a file the producer wrote and acknowledged, not a hand-built
dictionary.
"""
import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

from local_observe.http import JsonClient
from local_observe.inventory.validation import canonical, timestamp, utc_text
from local_observe.platform import anomaly, anomaly_cursor, anomaly_migrate
from local_observe.platform.owner import exclusive_owner
from test_anomaly import (DurabilityFixture, NOW, PRODUCER, history, latest, private, series_entry)

ROOT = Path(__file__).resolve().parents[1]
OTHER_SQL = ('SELECT toUnixTimestamp(t) AS ts, sum(v) AS v FROM signoz_traces.distributed_timeseries '
             'WHERE t >= {start_s:UInt64} AND t < {end_s:UInt64} GROUP BY ts ORDER BY ts FORMAT JSON')
OTHER_SHA = hashlib.sha256(OTHER_SQL.encode()).hexdigest()
MIGRATED = 'cursor-schema2.json'


def enabled_entry(**overrides) -> dict:
    """One series with coverage alerts on, at the same knobs the disabled fixture runs with."""
    return series_entry(min_points=4, window_days=14, coverage_unjudgeable_windows=2, **overrides)


def disabled_entry(**overrides) -> dict:
    """The same series with the knob omitted entirely, which is the schema-1 binding."""
    return series_entry(min_points=4, window_days=14, **overrides)


def latency_entry(**options) -> dict:
    """A second configured series, so a mixed enabled/disabled document is reachable."""
    return disabled_entry(id='demo-latency', sql=OTHER_SQL, sql_sha256=OTHER_SHA, **options)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class MigrationFixture(DurabilityFixture):
    """A schema-1 cursor produced by real rounds, plus the command's invocation helpers."""

    def config_file(self, name: str, *entries: dict, **defaults: object) -> Path:
        """Write and return a configuration document the command may be given as ``--config``."""
        path = self.root / name
        path.write_text(json.dumps({'series': list(entries) or [enabled_entry()], **defaults}),
                        encoding='utf-8')
        return path

    def target(self) -> Path:
        """The mixed target: the first series coverage-enabled, the second left disabled."""
        return self.config_file('target.json', enabled_entry(), latency_entry())

    def output(self, name: str = MIGRATED) -> Path:
        return self.cursor_directory / name

    def dry_run(self, *, cursor: Path | None = None, config: Path | None = None,
                source: str = PRODUCER.identity, digest: str | None = None,
                output: Path | None = None) -> dict:
        source_file = cursor if cursor is not None else self.cursor
        return anomaly_migrate.migrate(
            cursor_path=source_file,
            output_path=output if output is not None else self.output(),
            config_path=config if config is not None else self.target(), source=source,
            expected_sha256=digest if digest is not None else sha256_of(source_file), apply=False)

    def apply(self, **options: object) -> dict:
        arguments: dict = {'cursor_path': self.cursor, 'output_path': self.output(),
                           'config_path': self.target(), 'source': PRODUCER.identity,
                           'expected_sha256': sha256_of(self.cursor), 'apply': True}
        arguments.update(options)      # type: ignore[arg-type]
        return anomaly_migrate.migrate(**arguments)

    def refused(self, call):
        """Run *call*, require that it refused, and pin that the input kept its bytes."""
        before = self.cursor.read_bytes() if self.cursor.exists() else None
        with self.assertRaises(ValueError) as caught:
            call()
        self.assertEqual(before, self.cursor.read_bytes() if self.cursor.exists() else None,
                         'a refused migration never touches the input')
        return caught.exception

    def code(self, call) -> tuple[str, str]:
        """Return ``(exception class, refusal code)`` for a refusal, which every test asserts on."""
        exception = self.refused(call)
        return type(exception).__name__, getattr(exception, 'code', '')

    def migrated(self, *, source: str = PRODUCER.identity) -> dict:
        """Return the applied output **as the enabled producer would load it**, refusing if it cannot."""
        return anomaly_cursor.load(self.output(), source=source, coverage=True)

    def listing(self) -> list[str]:
        return sorted(item.name for item in self.cursor_directory.iterdir())

    def pending_of(self, document: dict, series_id: str = 'demo-load') -> dict:
        return document['series'][series_id]['pending']

    def write_back(self, document: object) -> None:
        self.cursor.write_text(canonical(document), encoding='utf-8')


class DryRunTests(MigrationFixture):
    """The default mode: everything checked, nothing reserved, nothing written."""

    def healthy(self) -> dict:
        """One acknowledged round on a schema-1 cursor with nothing owed, and its summary."""
        summary, _, _ = self.run_round(self.configuration(disabled_entry()), history() + latest(30.0))
        self.assertEqual(summary['series'][0]['result'], 'delivered')
        return summary

    def test_a_healthy_schema_one_cursor_reports_as_migratable_and_stays_alone(self):
        self.healthy()
        before = self.cursor.read_bytes()
        report = self.dry_run()
        self.assertEqual(report['status'], 'dry_run')
        self.assertEqual(report['pending'], 0, 'nothing is owed, so the report must not claim a batch')
        self.assertEqual(report['input_sha256'], sha256_of(self.cursor))
        self.assertEqual(before, self.cursor.read_bytes())
        self.assertEqual(self.listing(), ['anomaly-cursor.json'],
                         'a dry run creates no output, no temporary file and no owner lock')

    def test_no_transport_is_constructed_or_used_in_dry_run_or_in_a_refusal(self):
        self.healthy()
        def never(*args, **kwargs):
            raise AssertionError('the migration must not talk to a store or the platform')

        with mock.patch.object(JsonClient, 'request', never), mock.patch.object(
                anomaly.ClickHouse, 'query', never):
            self.dry_run()
            self.assertEqual(self.code(lambda: self.dry_run(config=self.config_file(
                'flat.json', disabled_entry())))[1], 'target_coverage_disabled')
        self.assertEqual(self.listing(), ['anomaly-cursor.json'])

    def test_the_reported_output_digest_is_the_bytes_apply_writes(self):
        self.healthy()
        report = self.dry_run()
        written = self.apply()
        self.assertEqual(written['output_sha256'], report['output_sha256'],
                         'the dry run that says yes describes the file --apply makes')
        self.assertEqual(written['input_sha256'], report['input_sha256'])

    def test_a_missing_input_is_refused_before_anything_else(self):
        code, reason = self.code(lambda: anomaly_migrate.migrate(
            cursor_path=self.cursor_directory / 'absent.json', output_path=self.output(),
            config_path=self.target(), source=PRODUCER.identity,
            expected_sha256='0' * 64, apply=True))
        self.assertEqual((code, reason), ('Refusal', 'input_absent'))
        self.assertEqual(self.listing(), [])

    def test_a_digest_that_is_not_a_sha256_is_refused(self):
        self.healthy()
        for value in ('', 'zz' * 32, '0' * 63, '0' * 65, 'A' * 64, 'x'):
            with self.subTest(value=value):
                self.assertEqual(self.code(lambda: self.dry_run(digest=value)),
                                 ('Refusal', 'digest_malformed'))

    def test_hash_drift_refuses_the_run_that_no_longer_describes_the_file(self):
        """The dry run green-lights *these* bytes; --apply re-checks them under the lock."""
        self.healthy()
        report = self.dry_run()
        self.cursor.write_bytes(self.cursor.read_bytes() + b' ')
        self.assertEqual(self.code(lambda: anomaly_migrate.migrate(
            cursor_path=self.cursor, output_path=self.output(), config_path=self.target(),
            source=PRODUCER.identity, expected_sha256=report['input_sha256'], apply=True)),
            ('Refusal', 'input_digest_mismatch'))
        self.assertNotIn(MIGRATED, self.listing(),
                         'drift writes no destination (the owner lock file the lock itself made stays '
                         'behind, as it does for any lock: its presence says nothing about an owner)')

    def test_a_source_that_changes_between_the_hash_and_the_load_is_refused(self):
        """``load`` re-opens the path, so the bytes it saw are re-checked against the ones hashed."""
        self.healthy()
        real = anomaly_cursor.load

        def swapping(path, **kwargs):
            document = real(path, **kwargs)
            self.cursor.write_bytes(self.cursor.read_bytes() + b' ')   # a swap after the read
            return document

        with mock.patch.object(anomaly_cursor, 'load', swapping), self.assertRaises(
                anomaly_migrate.Refusal) as caught:
            self.dry_run()
        self.assertEqual(caught.exception.code, 'input_digest_mismatch')
        self.assertFalse(self.output().exists())

    def test_a_different_loaded_snapshot_is_refused_even_if_source_bytes_return(self):
        self.healthy()
        before = self.cursor.read_bytes()
        real = anomaly_cursor.load

        def other_snapshot(path, **kwargs):
            document = real(path, **kwargs)
            document['series']['demo-load']['refusals'] += 1
            return document

        with mock.patch.object(anomaly_cursor, 'load', other_snapshot):
            self.assertEqual(self.code(self.dry_run), ('Refusal', 'source_changed'))
        self.assertEqual(before, self.cursor.read_bytes())
        self.assertFalse(self.output().exists())

    def test_migration_growth_past_the_byte_limit_refuses_in_both_modes(self):
        self.healthy()
        before = self.cursor.read_bytes()
        with mock.patch.object(anomaly_cursor, 'MAX_CURSOR_BYTES', len(before)):
            for action in (self.dry_run, self.apply):
                self.assertEqual(self.code(action), ('Refusal', 'output_too_large'))
                self.assertFalse(self.output().exists())
        self.assertEqual(before, self.cursor.read_bytes())

    def test_a_configuration_with_no_enabled_threshold_has_nothing_to_migrate(self):
        self.healthy()
        self.assertEqual(self.code(lambda: self.dry_run(
            config=self.config_file('flat.json', disabled_entry()))),
            ('Refusal', 'target_coverage_disabled'))

    def test_a_cursor_owned_by_another_process_refuses_the_apply(self):
        """The producer holds this lock for its whole life, so a live producer blocks the migration."""
        self.healthy()
        report = self.dry_run()
        with exclusive_owner(self.cursor):
            self.assertEqual(self.code(lambda: anomaly_migrate.migrate(
                cursor_path=self.cursor, output_path=self.output(), config_path=self.target(),
                source=PRODUCER.identity, expected_sha256=report['input_sha256'], apply=True)),
                ('Refusal', 'source_locked'))
        self.assertNotIn(MIGRATED, self.listing(), 'the refused apply created no destination')

    def test_a_dry_run_never_takes_the_lock_an_apply_needs(self):
        self.healthy()
        self.dry_run()
        with exclusive_owner(self.cursor):
            self.assertEqual(self.dry_run()['status'], 'dry_run')

    def test_the_producer_itself_still_refuses_the_schema_one_file_with_coverage_on(self):
        """This command is the only door: a round against the same knobs still refuses and still writes
        nothing, so no restart can reach a migration by accident."""
        self.healthy()
        before = self.cursor.read_bytes()
        with self.assertRaisesRegex(anomaly_cursor.CursorRefusal, 'migration'):
            self.run_round(self.configuration(enabled_entry()), history() + latest(11.0))
        self.assertEqual(before, self.cursor.read_bytes())


class PendingPreservationTests(MigrationFixture):
    """The card's reason for existing: an owed batch survives as the same request."""

    def batch_round(self, status: str) -> tuple[list, dict]:
        """A real round whose event POST was refused, so the cursor holds that batch.

        *status* picks which ordinary verdict the window earned: an out-of-band point fires, an
        in-band point resolves. Both are real `_verdict` outputs, not payloads this file invented.
        Named apart from :meth:`DurabilityFixture.owed`, which answers "how many windows does this
        series still lag by" and takes configuration entries, not a verdict word.
        """
        rows = history() + latest(30.0 if status == 'firing' else 11.0)
        summary, platform, _ = self.run_round(self.configuration(disabled_entry()), rows,
                                              refuse=('/v1/events',))
        self.assertEqual(summary['series'][0]['result'], 'refused')
        held = copy.deepcopy(self.held_batch())
        self.assertEqual(held['event']['status'], status)
        return platform.bodies(), held

    def owed_batch(self, status: str) -> tuple[list, dict]:
        """Alias of :meth:`batch_round` at the call sites that read as "make me a debt"."""
        return self.batch_round(status)

    def test_the_delivery_is_the_stored_batch_itself_and_the_next_round_posts_it(self):
        owed_bytes, held = self.owed_batch('firing')
        original = self.cursor_document()
        entry = original['series']['demo-load']
        before = self.cursor.read_bytes()
        report = self.apply()
        self.assertEqual(report['status'], 'migrated')
        self.assertEqual(report['pending'], 1)
        self.assertEqual(before, self.cursor.read_bytes(), 'success never touches the input either')

        migrated = self.migrated()
        self.assertEqual(migrated['schema_version'], anomaly_cursor.COVERAGE_SCHEMA_VERSION)
        self.assertEqual(migrated['source'], original['source'])
        self.assertEqual(migrated['last_served'], original['last_served'],
                         'the round-robin position is not the migration\'s to reset')
        state = migrated['series']['demo-load']
        for field in ('last_acked_end', 'anchored_at', 'anchor_logged', 'owed_end', 'delivered',
                      'no_verdict', 'refusals'):
            self.assertEqual(state[field], entry[field], f'{field} is a stored fact, not a migration input')
        enabled = anomaly.load_config(self.target())['series'][0]
        self.assertEqual(state['binding'], anomaly_cursor.series_binding(enabled),
                         'the enabled entry carries the enabled binding')
        self.assertNotEqual(entry['binding'], state['binding'])
        self.assertEqual(state['coverage'], anomaly_cursor.coverage_initial(),
                         'no coverage history is invented for windows this cursor never judged')
        pending = self.pending_of(migrated)
        self.assertEqual(set(pending), set(anomaly_cursor.COVERAGE_PENDING_KEYS))
        self.assertEqual(pending['outcome'], 'delivered', 'the verdict is read from the stored event')
        self.assertEqual(pending['deliveries'], [held],
                         'the one delivery is the schema-1 batch, field for field')
        self.assertEqual(canonical(pending['deliveries'][0]['sample']), canonical(held['sample']))
        self.assertEqual(canonical(pending['deliveries'][0]['event']), canonical(held['event']))
        self.assertEqual(pending['coverage_after'],
                         anomaly_cursor.coverage_transition(anomaly_cursor.coverage_initial(),
                                                            'delivered', 2)[0],
                         'coverage_after is the real transition of a zero history, not a guess')

        # The real enabled round over the migrated file, with the out-of-band point removed so a
        # re-read of the series could not imitate the owed answer.
        _, replay, reader = self.run_round(self.configuration(enabled_entry()), history(), now=NOW,
                                           cursor=self.output())
        self.assertEqual(reader.calls, 0, 'a replayed batch is never re-read from the store')
        self.assertEqual(replay.bodies(), owed_bytes,
                         'the migrated cursor replays the owed bytes, it does not re-judge the window')
        self.assertEqual([event['source_event_id'] for event in replay.events],
                         [held['event']['source_event_id']])
        settled = self.migrated()
        self.assertIsNone(settled['series']['demo-load']['pending'])
        self.assertEqual(settled['series']['demo-load']['last_acked_end'],
                         utc_text(timestamp(self.window()['end'])))

    def test_the_replayed_ack_is_the_first_judgeable_window_the_file_remembers(self):
        self.owed_batch('firing')
        self.apply()
        self.assertFalse(self.migrated()['series']['demo-load']['coverage']['previously_judgeable'],
                         'before an acknowledgement, the enabled deployment remembers no history')
        self.run_round(self.configuration(enabled_entry()), history(), now=NOW, cursor=self.output())
        coverage = self.migrated()['series']['demo-load']['coverage']
        self.assertTrue(coverage['previously_judgeable'],
                        'the acknowledgement is what earns the history, through the real transition')
        self.assertEqual(coverage['consecutive_unjudgeable'], 0)
        self.assertFalse(coverage['coverage_open'], 'a judgeable window opens no coverage episode')

    def test_a_resolved_batch_replays_as_the_same_in_band_event(self):
        owed_bytes, held = self.owed_batch('resolved')
        self.apply()
        self.assertEqual(self.pending_of(self.migrated())['outcome'], 'recovered')
        _, replay, reader = self.run_round(self.configuration(enabled_entry()), history() + latest(30.0),
                                           now=NOW, cursor=self.output())
        self.assertEqual(reader.calls, 0)
        self.assertEqual(replay.bodies(), owed_bytes,
                         'an in-band verdict is owed the same bytes after the migration as before')
        self.assertEqual(replay.events[0]['source_event_id'], held['event']['source_event_id'])

    def test_no_acked_window_moves_when_the_batch_is_replayed(self):
        """A migration that acked anything would be a monitor acking its own undelivered report."""
        self.owed_batch('firing')
        acked = self.cursor_document()['series']['demo-load']['last_acked_end']
        counters = {field: self.cursor_document()['series']['demo-load'][field]
                    for field in ('delivered', 'no_verdict', 'refusals')}
        self.apply()
        state = self.migrated()['series']['demo-load']
        self.assertEqual(state['last_acked_end'], acked)
        self.assertEqual({field: state[field] for field in counters}, counters)
        self.assertEqual(state['owed_end'], utc_text(timestamp(self.window()['end'])),
                         'the window stays owed, because it still is')

    def test_a_pending_batch_the_cursor_could_not_have_written_refuses_the_migration(self):
        self.owed_batch('firing')
        pristine = self.cursor_document()
        for fault in ('nested-list', 'missing-event', 'digest', 'kind', 'window-shifted'):
            document = copy.deepcopy(pristine)
            held = document['series']['demo-load']['pending']
            if fault == 'nested-list':
                document['series']['demo-load']['pending'] = [held]
            elif fault == 'missing-event':
                del held['event']
            elif fault == 'digest':
                held['event_sha256'] = '0' * 64
            elif fault == 'kind':
                held['event']['kind'] = 'coverage'
            else:
                held['window']['end'] = utc_text(timestamp(held['window']['end'])
                                                 + dt.timedelta(seconds=3600))
            self.write_back(document)
            with self.subTest(fault=fault):
                exception = self.refused(lambda: self.dry_run())
                self.assertIsInstance(exception, anomaly_cursor.CursorRefusal)

    def test_a_cursor_that_repeats_a_key_is_damage_and_stays_damage(self):
        self.owed_batch('firing')
        text = self.cursor.read_text(encoding='utf-8')
        self.cursor.write_text(text.replace('"source":', '"source": "x", "source":', 1), encoding='utf-8')
        with self.assertRaisesRegex(anomaly_cursor.CursorRefusal, 'repeats a key'):
            self.dry_run()


class MixedSeriesTests(MigrationFixture):
    """Coverage is per series, so a migration moves a file whose entries are not alike."""

    def two_series(self) -> tuple[list, dict]:
        """One round over two schema-1 series, both refused, so both hold a batch."""
        summary, platform, _ = self.run_round(self.configuration(disabled_entry(), latency_entry()),
                                              history() + latest(30.0), refuse=('/v1/events',))
        self.assertEqual([row['result'] for row in summary['series']], ['refused', 'refused'])
        return platform.bodies(), copy.deepcopy(self.cursor_document())

    def test_enabled_and_disabled_entries_migrate_under_their_own_rules(self):
        _, original = self.two_series()
        self.apply()
        migrated = self.migrated()
        self.assertEqual(sorted(migrated['series']), ['demo-latency', 'demo-load'])
        enabled = anomaly.load_config(self.target())['series']
        for series in enabled:
            state, stored = migrated['series'][series['id']], original['series'][series['id']]
            self.assertEqual({key: value for key, value in state.items()
                              if key not in ('binding', 'pending', 'coverage')},
                             {key: value for key, value in stored.items()
                              if key not in ('binding', 'pending')},
                             f'{series["id"]} kept its positions, counters and round-robin state')
            self.assertEqual(self.pending_of(migrated, series['id'])['deliveries'], [stored['pending']],
                             f'{series["id"]} still owes the bytes it owed')
            self.assertEqual(state['coverage'], anomaly_cursor.coverage_initial())
            self.assertEqual(state['binding'], anomaly_cursor.series_binding(series))
            if anomaly_cursor.coverage_threshold(series):
                self.assertNotEqual(state['binding'], stored['binding'],
                                    'the enabled entry is the only one whose binding moves')
            else:
                self.assertEqual(state['binding'], stored['binding'],
                                 'a disabled entry keeps the binding it already proved')
        self.assertEqual(migrated['last_served'], original['last_served'])

    def test_both_owed_batches_survive_and_the_enabled_round_posts_all_of_them(self):
        owed_bytes, _ = self.two_series()
        report = self.apply()
        self.assertEqual(report['pending'], 2)
        _, replay, reader = self.run_round(self.configuration(enabled_entry(), latency_entry()),
                                           history(), now=NOW, cursor=self.output())
        self.assertEqual(reader.calls, 0)
        self.assertEqual(sorted(replay.bodies()), sorted(owed_bytes),
                         'four owed bodies come back out as the same four bodies')
        for state in self.migrated()['series'].values():
            self.assertIsNone(state['pending'], 'both debts are settled by the replay, not by the file')

    def test_a_series_the_target_configuration_dropped_refuses_the_migration(self):
        """A retained entry holds a batch nobody would replay; that is the operator's to resolve."""
        self.two_series()
        self.assertEqual(self.code(lambda: self.dry_run(config=self.config_file(
            'one.json', enabled_entry()))), ('CursorRefusal', ''))

    def test_a_series_added_to_the_target_needs_no_entry_and_is_not_invented(self):
        self.run_round(self.configuration(disabled_entry()), history() + latest(30.0))
        report = self.apply(config_path=self.config_file('grown.json', enabled_entry(), latency_entry()))
        migrated = self.migrated()
        self.assertEqual(sorted(migrated['series']), ['demo-load'],
                         'a newly configured series starts from a fresh entry, not a migrated one')
        self.assertEqual(report['series'], 1)


class BindingTests(MigrationFixture):
    """Only the approved threshold may move a binding; everything else is a refusal."""

    def with_batch(self) -> None:
        self.run_round(self.configuration(disabled_entry()), history() + latest(30.0),
                       refuse=('/v1/events',))
        self.assertIsNotNone(self.held_batch())

    def test_a_knob_that_moved_after_the_cursor_was_written_refuses(self):
        self.with_batch()
        exception = self.refused(lambda: self.dry_run(
            config=self.config_file('retuned.json', enabled_entry(k=4))))
        self.assertIsInstance(exception, anomaly_cursor.CursorRefusal)
        self.assertIn('underneath the cursor', str(exception))

    def test_a_sql_pin_that_moved_after_the_cursor_was_written_refuses(self):
        self.with_batch()
        exception = self.refused(lambda: self.dry_run(
            config=self.config_file('repinned.json',
                                    enabled_entry(sql=OTHER_SQL, sql_sha256=OTHER_SHA))))
        self.assertIsInstance(exception, anomaly_cursor.CursorRefusal)
        self.assertIn('underneath the cursor', str(exception))

    def test_a_stored_binding_nobody_produces_refuses(self):
        self.with_batch()
        document = self.cursor_document()
        document['series']['demo-load']['binding'] = 'a' * 64
        self.write_back(document)
        exception = self.refused(lambda: self.dry_run())
        self.assertIsInstance(exception, anomaly_cursor.CursorRefusal)
        self.assertIn('underneath the cursor', str(exception))

    def test_a_foreign_producer_identity_refuses(self):
        self.with_batch()
        exception = self.refused(lambda: self.dry_run(source='someone-else'))
        self.assertIsInstance(exception, anomaly_cursor.CursorRefusal)
        self.assertIn('different producer identity', str(exception))

    def test_a_stored_batch_the_configuration_no_longer_authorises_refuses(self):
        """The resource moved, so the owed event belongs to another series: refuse, do not re-bind."""
        self.with_batch()
        document = self.cursor_document()
        held = document['series']['demo-load']['pending']
        for other in (document['series']['demo-load']['pending']['event']['evidence'][0], held['event']):
            other['resource_id'] = '00000000-0000-0000-0000-000000000000'
        held['event_sha256'] = anomaly_cursor.payload_digest(held['event'])
        self.write_back(document)
        exception = self.refused(lambda: self.dry_run())
        self.assertIsInstance(exception, anomaly_cursor.CursorRefusal)


class InputShapeTests(MigrationFixture):
    """What the command refuses to read as a migration candidate, and what it says when it does."""

    def healthy(self) -> dict:
        self.run_round(self.configuration(disabled_entry()), history() + latest(30.0))
        return self.cursor_document()

    def test_a_version_that_is_not_schema_one_is_refused_without_a_read_of_the_schema(self):
        document = self.healthy()
        for version in (2, 3, 0, True, 1.0, '1', None):
            self.write_back({**document, 'schema_version': version})
            with self.subTest(version=version):
                self.assertEqual(self.code(lambda: self.dry_run()),
                                 ('Refusal', 'input_not_schema_one'))

    def test_a_schema_one_entry_may_not_already_carry_coverage(self):
        document = self.healthy()
        for entry in document['series'].values():
            entry['coverage'] = anomaly_cursor.coverage_initial()
        self.write_back(document)
        exception = self.refused(lambda: self.dry_run())
        self.assertIsInstance(exception, anomaly_cursor.CursorRefusal)
        self.assertIn('unknown or missing fields', str(exception))

    def test_a_file_that_is_not_the_cursor_document_is_refused(self):
        self.healthy()
        for text in ('not json', '[]', '{"schema_version": 1}', '{"schema_version": 1, "junk": 1}'):
            self.cursor.write_text(text, encoding='utf-8')
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.dry_run()

    def test_a_file_larger_than_the_cursor_ceiling_is_refused(self):
        self.healthy()
        self.cursor.write_bytes(self.cursor.read_bytes() + b' ' * anomaly_cursor.MAX_CURSOR_BYTES)
        self.assertEqual(self.code(lambda: self.dry_run(digest='z' * 64)),
                         ('Refusal', 'digest_malformed'),
                         'a malformed digest is refused before the file is even opened')
        self.assertEqual(self.code(lambda: self.dry_run(digest='0' * 64)),
                         ('Refusal', 'input_too_large'),
                         'a file past the cursor ceiling is damage, not a migration candidate')

    def test_a_symlinked_cursor_is_refused(self):
        self.healthy()
        link = self.cursor_directory / 'alias.json'
        try:
            link.symlink_to(self.cursor)
        except OSError as exc:                                # host withholds link creation
            self.skipTest(f'symlink creation unavailable ({type(exc).__name__})')
        self.assertEqual(self.code(lambda: self.dry_run(cursor=link)), ('Refusal', 'input_symlink'))

    def test_a_symlinked_input_ancestor_is_refused_before_the_bytes_are_read(self):
        self.healthy()
        with mock.patch.object(anomaly_cursor, 'symlink_present',
                               lambda candidate: candidate == self.cursor_directory):
            self.assertEqual(self.code(lambda: self.dry_run())[1], 'input_parent_unsafe')

    def test_a_symlinked_output_ancestor_is_refused_while_the_input_stays_usable(self):
        """Both paths are checked: writing into a linked tree leaks the same payloads elsewhere."""
        self.healthy()
        elsewhere = private(self.root / 'elsewhere')
        destination = elsewhere / MIGRATED
        with mock.patch.object(anomaly_cursor, 'symlink_present',
                               lambda candidate: candidate == elsewhere):
            self.assertEqual(self.code(lambda: self.dry_run(output=destination))[1],
                             'output_parent_unsafe')

    def test_a_group_readable_parent_is_refused(self):
        self.healthy()
        if os.name == 'nt':
            self.skipTest('POSIX mode bits do not exist on Windows')
        os.chmod(self.cursor_directory, 0o770)
        if self.cursor_directory.stat().st_mode & 0o777 != 0o770:
            self.skipTest('this host does not honour directory modes, so the refusal cannot be observed')
        self.assertEqual(self.code(lambda: self.dry_run())[1], 'input_parent_unsafe')

    def test_a_parent_that_does_not_exist_is_refused(self):
        self.healthy()
        self.assertEqual(self.code(lambda: self.dry_run(
            output=self.root / 'absent' / 'new.json'))[1], 'output_parent_unsafe')


class DestinationTests(MigrationFixture):
    """The output is a new file, exclusively created, and never the input."""

    def healthy(self, *, refuse: tuple = ()) -> None:
        self.run_round(self.configuration(disabled_entry()), history() + latest(30.0), refuse=refuse)

    def test_the_same_path_as_the_input_is_refused_in_both_modes(self):
        self.healthy()
        for apply in (False, True):
            with self.subTest(apply=apply):
                self.assertEqual(self.code(lambda: anomaly_migrate.migrate(
                    cursor_path=self.cursor, output_path=self.cursor, config_path=self.target(),
                    source=PRODUCER.identity, expected_sha256=sha256_of(self.cursor), apply=apply)),
                    ('Refusal', 'output_same_as_input'))
        self.assertEqual(self.listing(), ['anomaly-cursor.json'])

    def test_a_path_that_aliases_the_input_is_refused_too(self):
        self.healthy()
        alias = self.cursor_directory / '.' / self.cursor.name
        self.assertEqual(self.code(lambda: anomaly_migrate.migrate(
            cursor_path=self.cursor, output_path=alias, config_path=self.target(),
            source=PRODUCER.identity, expected_sha256=sha256_of(self.cursor), apply=True)),
            ('Refusal', 'output_same_as_input'))

    def test_an_existing_output_is_never_overwritten(self):
        self.healthy()
        destination = self.output()
        destination.write_text('somebody else made this', encoding='utf-8')
        for apply in (False, True):
            with self.subTest(apply=apply):
                self.assertEqual(self.code(lambda: self.apply(output_path=destination) if apply else
                                           self.dry_run(output=destination)),
                                 ('Refusal', 'output_exists'))
        self.assertEqual(destination.read_text(encoding='utf-8'), 'somebody else made this')

    def test_a_repeated_apply_refuses_rather_than_replacing_its_own_output(self):
        self.healthy()
        first = self.apply()
        self.assertTrue(self.output().is_file())
        self.assertEqual(self.code(lambda: self.apply()), ('Refusal', 'output_exists'))
        self.assertEqual(sha256_of(self.output()), first['output_sha256'],
                         'the refusal did not rewrite the file it refused to replace')

    def test_a_race_that_creates_the_output_after_the_check_is_refused(self):
        """``O_EXCL`` is the last word: an output appearing between the check and the open loses."""
        self.healthy()
        destination = self.output()
        real = anomaly_migrate._output_candidate

        def sneaky(path: Path) -> None:
            real(path)
            if not path.exists():
                path.write_text('created by another writer', encoding='utf-8')

        with mock.patch.object(anomaly_migrate, '_output_candidate', sneaky):
            self.assertEqual(self.code(lambda: self.apply()), ('Refusal', 'output_exists'))
        self.assertEqual(destination.read_text(encoding='utf-8'), 'created by another writer',
                         'this command does not delete a file it did not create')

    def test_a_failed_sync_retains_the_incomplete_output_as_unverified(self):
        self.healthy()
        before = self.cursor.read_bytes()
        with mock.patch.object(anomaly_migrate.os, 'fsync', side_effect=OSError('disk is gone')):
            self.assertEqual(self.code(lambda: self.apply()),
                             ('Refusal', 'output_write_unsynced'))
        self.assertTrue(self.output().is_file(),
                        'the leftover is kept and reported, not hidden by deleting it')
        self.assertEqual(before, self.cursor.read_bytes())

    def test_a_destination_that_cannot_be_read_back_is_not_reported_as_a_busy_producer(self):
        """The readback sits inside the lock scope; its failure must keep its own code."""
        self.healthy()
        real = Path.read_bytes
        def unreadable(path):
            if path == self.output():
                raise OSError('the volume went away')
            return real(path)

        with mock.patch.object(Path, 'read_bytes', unreadable):
            self.assertEqual(self.code(lambda: self.apply())[1], 'output_readback_unreadable')
        self.assertTrue(self.output().is_file(), 'the leftover is kept and reported')

    def test_the_output_is_the_private_canonical_file_the_producer_can_read(self):
        self.healthy()
        self.apply()
        payload = self.output().read_bytes()
        self.assertEqual(payload, canonical(self.migrated()).encode(),
                         'the file is exactly the canonical document, one line')
        if os.name != 'nt':
            self.assertEqual(self.output().stat().st_mode & 0o777, 0o600)

    def test_the_report_names_digests_and_counts_and_no_payload(self):
        self.healthy(refuse=('/v1/events',))
        held = self.held_batch()
        report = self.apply()
        self.assertEqual(sorted(report), ['bytes', 'input', 'input_sha256', 'output',
                                          'output_sha256', 'pending', 'series', 'status'])
        printed = json.dumps(report)
        for needle in (held['sample']['sample_id'], held['event']['source_event_id'],
                       held['event']['rule_id'], held['evidence_sha256'], held['event_sha256']):
            self.assertNotIn(needle, printed, 'a migration report is not a payload dump')


class CommandTests(MigrationFixture):
    """The door an operator actually stands at: one JSON object on stdout, one exit code."""

    def argv(self, *extra: str, digest: str | None = None,
             source: str = PRODUCER.identity) -> list[str]:
        return ['--input', str(self.cursor), '--output', str(self.output()),
                '--config', str(self.target()), '--source', source,
                '--expected-sha256', digest if digest is not None else sha256_of(self.cursor), *extra]

    def invoke(self, argv: list[str]) -> tuple[int, dict]:
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            code = anomaly_migrate.main(argv)
        return code, json.loads(printed.getvalue())

    def test_dry_run_exits_zero_and_says_what_it_would_write(self):
        self.run_round(self.configuration(disabled_entry()), history() + latest(30.0))
        code, report = self.invoke(self.argv())
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'dry_run')
        self.assertFalse(self.output().exists())

    def test_apply_exits_zero_and_the_next_start_loads_the_result(self):
        self.run_round(self.configuration(disabled_entry()), history() + latest(30.0))
        code, report = self.invoke(self.argv('--apply'))
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'migrated')
        self.assertEqual(self.migrated()['schema_version'], anomaly_cursor.COVERAGE_SCHEMA_VERSION)

    def test_a_refusal_exits_one_and_prints_only_the_class(self):
        self.run_round(self.configuration(disabled_entry()), history() + latest(30.0))
        code, answer = self.invoke(self.argv('--apply', digest='0' * 64))
        self.assertEqual(code, 1)
        self.assertEqual(answer, {'status': 'error', 'error_type': 'Refusal'})
        self.assertFalse(self.output().exists())

    def test_a_cursor_refusal_exits_one_without_naming_the_file(self):
        self.run_round(self.configuration(disabled_entry()), history() + latest(30.0))
        argv = self.argv('--apply', source='someone-else')
        printed, logged = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(logged):
            code = anomaly_migrate.main(argv)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(printed.getvalue()), {'status': 'error',
                                                          'error_type': 'CursorRefusal'})

    def test_missing_required_flags_are_argparse_errors(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                anomaly_migrate.main(['--input', str(self.cursor)])
        self.assertEqual(caught.exception.code, 2)

    def test_the_module_runs_as_a_process_and_exits_one_on_a_refusal(self):
        """A real interpreter, so the exit code is the one a shell and a runbook see."""
        process = subprocess.run(
            [sys.executable, '-B', '-m', 'local_observe.platform.anomaly_migrate',
             '--input', str(self.cursor_directory / 'absent.json'), '--output', str(self.output()),
             '--config', str(self.target()), '--source', PRODUCER.identity,
             '--expected-sha256', '0' * 64],
            cwd=str(ROOT), env=dict(os.environ, PYTHONPATH=str(ROOT), PYTHONIOENCODING='utf-8'),
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
        self.assertEqual(process.returncode, 1, process.stderr[-2000:])
        self.assertEqual(json.loads(process.stdout), {'status': 'error', 'error_type': 'Refusal'})
        self.assertFalse(self.output().exists())


class PureFunctionTests(MigrationFixture):
    """The guards of the helper itself that no end-to-end path can reach, because the command builds
    the old configuration out of the new one."""

    def parts(self) -> tuple[dict, list, list]:
        self.run_round(self.configuration(disabled_entry()), history() + latest(30.0))
        legacy = anomaly.load_config(self.config_file('legacy.json', disabled_entry()))['series']
        target = anomaly.load_config(self.config_file('only.json', enabled_entry()))['series']
        document = anomaly_cursor.load(self.cursor, source=PRODUCER.identity)
        return document, legacy, target

    def migrate(self, document, legacy, target, versions):
        return anomaly_cursor.migrate_document(document, legacy=legacy, target=target,
                                              rule_versions=versions, source=PRODUCER.identity, now=NOW)

    def test_it_refuses_without_the_rule_version_of_a_series_it_must_replay(self):
        document, legacy, target = self.parts()
        with self.assertRaisesRegex(anomaly_cursor.CursorRefusal, 'rule_version'):
            self.migrate(document, legacy, target, {})

    def test_it_refuses_a_document_that_is_not_schema_one(self):
        document, legacy, target = self.parts()
        upgraded = self.migrate(document, legacy, target, {'demo-load': anomaly._rule_version(target[0])})
        with self.assertRaisesRegex(anomaly_cursor.CursorRefusal, 'schema-1'):
            self.migrate(upgraded, legacy, target, {'demo-load': anomaly._rule_version(target[0])})

    def test_it_refuses_an_all_disabled_target(self):
        document, legacy, _target = self.parts()
        with self.assertRaisesRegex(anomaly_cursor.CursorRefusal, 'coverage-enabled'):
            self.migrate(document, legacy, legacy, {'demo-load': 'a' * 16})

    def test_it_refuses_a_stored_series_the_old_configuration_does_not_name(self):
        document, _legacy, target = self.parts()
        other = anomaly.load_config(self.config_file('other.json', latency_entry()))['series']
        with self.assertRaisesRegex(anomaly_cursor.CursorRefusal, 'configuration the cursor was loaded'):
            self.migrate(document, other, target, {'demo-load': 'a' * 16})

    def test_it_never_mutates_the_document_it_was_handed(self):
        document, legacy, target = self.parts()
        before = canonical(document)
        self.migrate(document, legacy, target, {'demo-load': anomaly._rule_version(target[0])})
        self.assertEqual(before, canonical(document), 'migration is a pure function of its input')


if __name__ == '__main__':
    unittest.main()

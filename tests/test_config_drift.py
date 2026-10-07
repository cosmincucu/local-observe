"""The snapshot-tree drift producer (drift producer): what it emits, and the things it refuses to.

The fixture is a directory the operator's own job is assumed to write - declared resources and one
file each - so every expectation here is about *a digest moving*, never about a commit. Times are
fixed and window-aligned: :data:`NOW` sits five seconds inside a 300-second round whose watermark is
``12:00:00Z``, so the judged window is ``11:55:00Z..12:00:00Z`` and a reader can check the arithmetic
without running anything. Windows are written with `utc_text`, the same canonical form the platform
stores, because it carries microseconds and a hand-typed literal would not match.

Every emitted event is validated by the real thing (`state.validate_event`, reached directly and
through `Store.intake`), never by a mock of it: an event this producer is proud of and intake refuses
is the failure this card exists to prevent.
"""
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

from local_observe.inventory import index
from local_observe.inventory.validation import digest, read_document, timestamp, utc_text
from local_observe.platform import cli, configdrift
from local_observe.platform.state import EVENT_KINDS, Actor, Store, validate_event

ROOT = Path(__file__).resolve().parents[1]
DECLARED = ROOT / 'examples/inventory/declared.yaml'
RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
SECOND = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
UNDECLARED = '00000000-0000-4000-8000-000000000000'
SOURCE = 'config-drift-test'
PRODUCER = Actor(SOURCE, 'producer')
RULE = 'drift.router-running-config'
FIRST = timestamp('2026-08-05T12:00:05Z')
SECOND_ROUND = timestamp('2026-08-05T12:05:05Z')
THIRD = timestamp('2026-08-05T12:10:05Z')
FOURTH = timestamp('2026-08-05T12:15:05Z')
WATERMARK = timestamp('2026-08-05T12:00:00Z')
LATER_WATERMARK = timestamp('2026-08-05T12:05:00Z')
NOW = FIRST
LATER = SECOND_ROUND
INTERVAL = dt.timedelta(seconds=300)


def window(end: dt.datetime) -> dict[str, str]:
    """Return the aligned evaluation window a round judged at *end* carries on its events."""
    return {'start': utc_text(end - INTERVAL), 'end': utc_text(end)}


WINDOW = window(WATERMARK)
ORIGINAL = 'hostname router-01\nsnmp-server community public\n'
EDITED = 'hostname router-01\nsnmp-server community private\n'
# A third revision of the same artifact: what a change **after** an acknowledgement looks like, which is
# the case that used to be delivered to nobody.
REPLACED = 'hostname router-01\nsnmp-server community private\nip ssh version 2\n'


def sha256(text: str) -> str:
    """Return the digest the producer must report for *text*, taken over the bytes as stored."""
    return hashlib.sha256(text.encode()).hexdigest()


class Deliverer:
    """The delivery seam `tick` is given: records each event and intake-validates it for real.

    `intake` is called at the round's own instant, so a late-window event is judged against a clock
    that can accept it rather than against a fixture time five minutes earlier. `fail_with` makes the
    delivery refuse, which is how "the cursor is not advanced over a failed round" is tested without a
    network, a second process or a fake platform.
    """

    def __init__(self, store: Store, *, now: dt.datetime, fail_with: Exception | None = None) -> None:
        self.store, self.now, self.fail_with = store, now, fail_with
        self.events: list[dict] = []
        self.receipts: list[dict] = []

    def __call__(self, item: dict) -> None:
        if self.fail_with is not None:
            raise self.fail_with
        self.events.append(dict(item))
        self.receipts.append(self.store.intake(item, PRODUCER, now=self.now))


class Fixture(unittest.TestCase):
    """Shared scratch: a declared index, a platform store, a snapshot tree and a config document."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index = self.root / 'inventory.db'
        index.build(read_document(DECLARED), self.index, 'fixture')
        self.store = Store(self.root / 'state.db')
        self.tree = self.root / 'snapshots'
        self.cursor = self.root / 'state/drift-cursor.json'
        self.artifact = self.tree / RESOURCE / 'running-config'

    def write_artifact(self, text: str, *, resource: str = RESOURCE,
                       name: str = 'running-config') -> Path:
        """Put *text* where the producer expects that artifact, creating the tree when it is gone."""
        target = self.tree / resource / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8', newline='')
        return target

    def remove_tree(self) -> None:
        """Take the snapshot tree away in place: the config still names it, the mount is not there."""
        shutil.rmtree(self.tree)

    def document(self, **overrides) -> dict:
        """One valid configuration document, with *overrides* merged (``None`` removes a key)."""
        document: dict = {'root': str(self.tree), 'cursor': str(self.cursor),
                          'resources': [{'resource_id': RESOURCE, 'name': 'running-config',
                                         'rule_id': RULE}],
                          'interval_seconds': 300}
        for key, value in overrides.items():
            if value is None:
                document.pop(key, None)
            else:
                document[key] = value
        return document

    def write_json(self, document: object, name: str = 'drift.json') -> Path:
        """Write *document* as the config file the producer will be pointed at, and return its path."""
        path = self.root / name
        path.write_text(document if isinstance(document, str) else json.dumps(document),
                        encoding='utf-8')
        return path

    def config(self, **overrides) -> dict:
        """Return the validated form of :meth:`document`, written to disk and read back."""
        return configdrift.load_config(self.write_json(self.document(**overrides)))

    def run_tick(self, *, now: dt.datetime = NOW, config: dict | None = None,
                 deliverer: Deliverer | None = None) -> tuple[dict, Deliverer]:
        """Run one round against the shared tree and store; return its summary and what it delivered."""
        deliverer = deliverer or Deliverer(self.store, now=now)
        return configdrift.tick(self.index, config or self.config(), self.cursor, deliverer, now=now,
                                source=SOURCE), deliverer

    def remembered(self, config: dict | None = None) -> dict:
        """Return the cursor entry for the default artifact, as the producer just wrote it."""
        cursor = configdrift.load_cursor(self.cursor, config or self.config())
        return cursor['seen'][f'{RESOURCE}/running-config']

    def stored_events(self, database: Path, source: str = SOURCE) -> list[dict]:
        """Read the event payloads back out of the database the CLI just wrote."""
        with contextlib.closing(sqlite3.connect(database)) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute('SELECT payload FROM events WHERE source=?', (source,)).fetchall()
        return [json.loads(row['payload']) for row in rows]


class ConfigTests(Fixture):
    """Every knob, and the shape of the off switch (which must be an outcome, not a silence)."""

    def test_absent_config_turns_the_producer_off_with_one_info_line(self):
        """Proof the producer emits nothing without configuration: no event, no client, no cursor."""
        with self.assertLogs('local_observe.platform.configdrift', 'INFO') as captured:
            self.assertIsNone(configdrift.producer_config({}))
        self.assertEqual(len(captured.output), 1)
        self.assertIn('Config-drift producer is off', captured.output[0])
        self.assertEqual(captured.records[0].variable, configdrift.CONFIG_ENVIRONMENT)

    def test_a_blank_config_path_is_off_too(self):
        with self.assertLogs('local_observe.platform.configdrift', 'INFO'):
            self.assertIsNone(configdrift.producer_config({configdrift.CONFIG_ENVIRONMENT: '   '}))

    def test_main_reports_off_and_writes_nothing(self):
        """No configuration named: exit 0, one log line, and not one byte of the tree added.

        The scratch directory already holds this test's index and store, so the assertion is that the
        run added nothing - no cursor, no cursor directory, no owner lock beside either.
        """
        before = sorted(path.name for path in self.root.iterdir())
        with mock.patch.dict('os.environ', {}, clear=True), \
                self.assertLogs('local_observe.platform.configdrift', 'INFO') as captured:
            self.assertEqual(configdrift.main(), 0)
        self.assertEqual(len(captured.output), 1)
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), before)
        self.assertFalse(self.cursor.parent.exists())

    def test_main_refuses_a_named_file_it_cannot_read(self):
        environment = {configdrift.CONFIG_ENVIRONMENT: str(self.root / 'absent.json')}
        with mock.patch.dict('os.environ', environment, clear=True):
            self.assertEqual(configdrift.main(), 1)

    def test_defaults_are_the_documented_ones(self):
        config = self.config(interval_seconds=None)
        self.assertEqual(config['interval_seconds'], configdrift.DEFAULT_TICK_SECONDS)
        self.assertEqual(config['root'], self.tree)
        self.assertEqual(config['cursor'], self.cursor)
        self.assertIsNone(config['acknowledgements'],
                          'no acknowledgement root named must mean the resolve path is off, not guess one')
        self.assertEqual(config['resources'], [{'resource_id': RESOURCE, 'name': 'running-config',
                                                'rule_id': RULE}])

    def test_unusable_documents_are_refused(self) -> None:
        entry = {'resource_id': RESOURCE, 'name': 'running-config', 'rule_id': RULE}
        broken: list = [
            ('this is not json', 'a document that is not JSON'),
            (self.document(root=None), 'no root'),
            (self.document(cursor=None), 'no cursor'),
            (self.document(resources=None), 'no artifact list'),
            (self.document(root='snapshots'), 'a relative root'),
            (self.document(cursor='state/drift.json'), 'a relative cursor'),
            (self.document(acknowledgements='acks'), 'a relative acknowledgement root'),
            (self.document(loose=1), 'an unknown top-level key'),
            (self.document(interval_seconds=30), 'an interval below the floor'),
            (self.document(interval_seconds=86_401), 'an interval above the ceiling'),
            (self.document(interval_seconds=True), 'a boolean interval'),
            (self.document(interval_seconds='300'), 'a text interval'),
            (self.document(resources=[]), 'an empty artifact list'),
            (self.document(resources=[entry] * 33), 'more artifacts than the cursor may hold'),
            (self.document(resources=[{'resource_id': RESOURCE, 'name': 'running-config'}]),
             'an entry with no rule_id'),
            (self.document(resources=[{**entry, 'extra': 1}]), 'an entry with an unknown field'),
            (self.document(resources=[{**entry, 'resource_id': 'router-01'}]),
             'a resource_id that is not a canonical UUID'),
            (self.document(resources=[{**entry, 'name': '../escape'}]), 'a name that leaves the tree'),
            (self.document(resources=[{**entry, 'name': 'a/b'}]), 'a name with a forward slash'),
            (self.document(resources=[{**entry, 'name': 'a\\b'}]), 'a name with a backslash'),
            (self.document(resources=[{**entry, 'name': '-flag'}]), 'a name a tool reads as a flag'),
            (self.document(resources=[{**entry, 'name': 'bad*name'}]),
             'a name outside the allowed characters'),
            (self.document(resources=[entry, {**entry, 'resource_id': SECOND}]),
             'two artifacts sharing one rule_id'),
            (self.document(resources=[entry, {**entry, 'rule_id': 'drift.second'}]),
             'the same artifact named twice'),
            (self.document(resources=[{**entry, 'rule_id': 'r' * 122}]),
             'a rule_id too long once .coverage is appended'),
        ]
        for position, (document, reason) in enumerate(broken):
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                configdrift.load_config(self.write_json(document, f'broken-{position}.json'))

    def test_a_bounded_name_and_a_declared_uuid_are_what_the_load_accepts(self):
        config = configdrift.load_config(self.write_json(self.document(
            resources=[{'resource_id': SECOND, 'name': 'startup-config_2', 'rule_id': 'drift:ok-1'}])))
        self.assertEqual(config['resources'], [{'resource_id': SECOND, 'name': 'startup-config_2',
                                                'rule_id': 'drift:ok-1'}])


class SnapshotReaderTests(Fixture):
    """The reader is content-addressed and bounded: a file it may not hold is a file it will not read."""

    def test_the_digest_is_of_the_bytes_as_stored(self):
        target = self.write_artifact(ORIGINAL)
        snapshot = configdrift.read_snapshot(self.tree, RESOURCE, 'running-config')
        self.assertEqual(snapshot.sha256, hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual(snapshot.text, ORIGINAL)
        self.assertEqual((snapshot.resource_id, snapshot.name), (RESOURCE, 'running-config'))

    def test_a_file_above_the_byte_ceiling_is_refused(self):
        self.write_artifact('x' * (configdrift.MAX_SNAPSHOT_BYTES + 1))
        with self.assertRaises(ValueError):
            configdrift.read_snapshot(self.tree, RESOURCE, 'running-config')

    def test_a_file_at_the_ceiling_is_read(self):
        text = '#' + 'x' * (configdrift.MAX_SNAPSHOT_BYTES - 1)
        self.write_artifact(text)
        self.assertEqual(configdrift.read_snapshot(self.tree, RESOURCE, 'running-config').text, text)

    def test_undecodable_bytes_are_refused(self):
        self.artifact.parent.mkdir(parents=True, exist_ok=True)
        self.artifact.write_bytes(b'\xff\xfe\x00 not text')
        with self.assertRaises(ValueError):
            configdrift.read_snapshot(self.tree, RESOURCE, 'running-config')

    def test_a_missing_file_is_a_refusal_and_not_a_quiet_empty_snapshot(self):
        self.write_artifact(ORIGINAL, name='startup-config')  # the tree exists; this artifact does not
        with self.assertRaises(FileNotFoundError):
            configdrift.read_snapshot(self.tree, RESOURCE, 'running-config')

    def test_a_tree_that_is_not_there_says_so_differently(self):
        with self.assertRaises(NotADirectoryError):
            configdrift.read_snapshot(self.root / 'nowhere', RESOURCE, 'running-config')

    def test_a_symlink_is_refused(self):
        outside = self.root / 'elsewhere'
        outside.write_text(ORIGINAL, encoding='utf-8')
        self.artifact.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.artifact.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest('this platform does not let the test create a symlink')
        with self.assertRaises(ValueError):
            configdrift.read_snapshot(self.tree, RESOURCE, 'running-config')


class ComparisonTests(unittest.TestCase):
    """The compare step returns what the brief names, and refuses to invent a first change."""

    def test_a_first_sighting_has_nothing_to_drift_from(self):
        current = configdrift.Snapshot(RESOURCE, 'running-config', sha256(ORIGINAL), ORIGINAL)
        result = configdrift.compare(None, current)
        self.assertEqual((result.previous_sha256, result.current_sha256, result.diff),
                         (None, sha256(ORIGINAL), ''))
        self.assertFalse(result.changed)

    def test_identical_content_produces_no_change_and_no_diff(self):
        seen = configdrift.LastSeen(sha256(ORIGINAL), ORIGINAL)
        result = configdrift.compare(seen, configdrift.Snapshot(RESOURCE, 'running-config',
                                                                sha256(ORIGINAL), ORIGINAL))
        self.assertFalse(result.changed)
        self.assertEqual(result.diff, '')

    def test_a_change_yields_a_deterministic_unified_diff_naming_both_digests(self):
        seen = configdrift.LastSeen(sha256(ORIGINAL), ORIGINAL)
        current = configdrift.Snapshot(RESOURCE, 'running-config', sha256(EDITED), EDITED)
        result = configdrift.compare(seen, current)
        self.assertTrue(result.changed)
        self.assertIn(f'--- {RESOURCE}/running-config@{sha256(ORIGINAL)[:12]}', result.diff)
        self.assertIn(f'+++ {RESOURCE}/running-config@{sha256(EDITED)[:12]}', result.diff)
        self.assertIn('-snmp-server community public', result.diff)
        self.assertIn('+snmp-server community private', result.diff)
        self.assertEqual(result.diff, configdrift.compare(seen, current).diff)


class TickTests(Fixture):
    """The outcomes the operator is owed, and the cursor discipline behind them."""

    def test_unchanged_content_emits_no_event(self):
        self.write_artifact(ORIGINAL)
        summary, delivered = self.run_tick()
        self.assertEqual(delivered.events, [])
        self.assertEqual(summary['result'], 'idle')
        self.assertEqual(summary['baselined'], 1)
        second, again = self.run_tick(now=LATER)
        self.assertEqual(again.events, [])
        self.assertEqual(second['result'], 'idle')
        self.assertEqual(second['changed'], 0)

    def test_a_changed_artifact_emits_one_drift_event_the_platform_accepts(self):
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.write_artifact(EDITED)
        summary, delivered = self.run_tick(now=LATER)
        self.assertEqual(len(delivered.events), 1)
        finding = delivered.events[0]
        self.assertEqual(summary['result'], 'delivered')
        self.assertEqual(finding['kind'], 'drift')
        self.assertEqual(finding['status'], 'firing')
        self.assertEqual(finding['resource_id'], RESOURCE)
        self.assertEqual(finding['rule_id'], RULE)
        self.assertEqual(finding['source'], SOURCE)
        self.assertEqual(finding['severity'], 'warning')
        validate_event(finding, LATER)
        self.assertEqual(delivered.receipts[0]['status'], 'accepted')
        self.assertEqual(delivered.receipts[0]['transition'], 'opened')

    def test_the_evidence_is_the_artifact_digest_in_a_window_ending_at_the_observation(self):
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.write_artifact(EDITED)
        _, delivered = self.run_tick(now=LATER)
        finding = delivered.events[0]
        evidence = finding['evidence'][0]
        self.assertEqual(len(finding['evidence']), 1)
        self.assertEqual(evidence['source'], SOURCE)
        self.assertEqual(evidence['query_type'], 'observed-snapshot')
        self.assertEqual(evidence['parameters'], {'rule_id': RULE, 'artifact_sha256': sha256(EDITED)})
        self.assertEqual(finding['window'], window(LATER_WATERMARK))
        self.assertEqual(evidence['window'], finding['window'])
        self.assertEqual(finding['observed_at'], finding['window']['end'])
        self.assertGreater(timestamp(evidence['expires_at']), timestamp(finding['window']['end']))

    def test_an_unreadable_tree_is_a_coverage_event_about_the_source(self):
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.remove_tree()
        summary, delivered = self.run_tick(now=LATER)
        self.assertEqual(summary['result'], 'unreadable')
        self.assertEqual(summary['unreadable'], 1)
        self.assertEqual(summary['evaluations'][0]['error'], 'snapshot_tree_absent')
        self.assertEqual(len(delivered.events), 1)
        coverage = delivered.events[0]
        self.assertEqual(coverage['kind'], 'coverage')
        self.assertEqual(coverage['status'], 'firing')
        self.assertEqual(coverage['rule_id'], RULE + '.coverage')
        self.assertEqual(coverage['resource_id'], RESOURCE)
        self.assertEqual(coverage['evidence'][0]['query_type'], 'source-heartbeat')
        validate_event(coverage, LATER)

    def test_ongoing_blindness_reports_once_and_recovery_closes_it(self):
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.remove_tree()
        self.run_tick(now=LATER, deliverer=Deliverer(self.store, now=LATER))
        summary, quiet = self.run_tick(now=THIRD, deliverer=Deliverer(self.store, now=THIRD))
        self.assertEqual(quiet.events, [], 'the same blindness filed a second coverage event')
        self.assertEqual(summary['result'], 'unreadable')
        self.write_artifact(ORIGINAL)
        _, recovered = self.run_tick(now=FOURTH, deliverer=Deliverer(self.store, now=FOURTH))
        self.assertEqual([(item['kind'], item['status']) for item in recovered.events],
                         [('coverage', 'resolved')])

    def test_an_artifact_that_changed_while_unreadable_is_still_drift(self):
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.remove_tree()
        self.run_tick(now=LATER, deliverer=Deliverer(self.store, now=LATER))
        self.write_artifact(EDITED)
        summary, delivered = self.run_tick(now=THIRD)
        self.assertEqual([item['kind'] for item in delivered.events], ['drift', 'coverage'])
        self.assertEqual(delivered.events[0]['evidence'][0]['parameters']['artifact_sha256'],
                         sha256(EDITED))
        self.assertEqual(delivered.events[1]['status'], 'resolved')
        self.assertEqual(summary['result'], 'delivered')

    def test_an_oversized_artifact_is_refused_and_says_so_as_coverage(self):
        self.write_artifact('x' * (configdrift.MAX_SNAPSHOT_BYTES + 1))
        summary, delivered = self.run_tick()
        self.assertEqual(summary['result'], 'unreadable')
        self.assertEqual(summary['evaluations'][0]['error'], 'snapshot_refused')
        self.assertEqual(delivered.events[0]['kind'], 'coverage')
        self.assertEqual(self.remembered(), {'sha256': None, 'text': None, 'unreadable': True},
                         'a refused artifact was remembered as if it had been read')

    def test_an_undeclared_resource_refuses_the_round_and_delivers_nothing(self):
        config = self.config(resources=[{'resource_id': UNDECLARED, 'name': 'running-config',
                                         'rule_id': RULE}])
        self.write_artifact(ORIGINAL, resource=UNDECLARED)
        deliverer = Deliverer(self.store, now=NOW)
        with self.assertRaises(ValueError):
            configdrift.tick(self.index, config, self.cursor, deliverer, now=NOW, source=SOURCE)
        self.assertEqual(deliverer.events, [])
        self.assertFalse(self.cursor.exists())

    def test_a_baselining_round_needs_no_delivery_and_remembers_the_digest(self):
        """A first sighting files nothing, and the baseline survives the round that took it."""
        self.write_artifact(ORIGINAL)
        summary, delivered = self.run_tick(deliverer=Deliverer(self.store, now=NOW,
                                                              fail_with=ValueError('unused')))
        self.assertEqual(delivered.events, [])
        self.assertEqual(summary['result'], 'idle')
        self.assertEqual(self.remembered(), {'sha256': sha256(ORIGINAL), 'text': ORIGINAL,
                                            'unreadable': False})

    def test_the_cursor_is_not_advanced_over_a_refused_delivery(self):
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.write_artifact(EDITED)
        with self.assertRaises(ValueError):
            self.run_tick(now=LATER, deliverer=Deliverer(self.store, now=LATER,
                                                         fail_with=ValueError('intake refused')))
        self.assertEqual(self.remembered()['sha256'], sha256(ORIGINAL))
        retry, delivered = self.run_tick(now=LATER)
        self.assertEqual(len(delivered.events), 1)
        self.assertEqual(retry['result'], 'delivered')

    def test_a_replayed_round_carries_the_same_retry_identity(self):
        """Aligned windows make a retry the same event: the platform folds it, no second incident.

        The round that delivered was told it failed - a lost response is a real transport outcome - so
        the cursor is still at the old digest and the next round recomputes the same verdict inside the
        same window.
        """
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.write_artifact(EDITED)
        first, delivered = self.run_tick(now=LATER)
        self.assertEqual(len(delivered.events), 1)
        stored = self.store.intake(delivered.events[0], PRODUCER, now=LATER)
        self.assertEqual(stored['status'], 'duplicate')
        self.assertEqual(stored['event_id'], delivered.receipts[0]['event_id'])
        self.assertEqual(first['window'], window(LATER_WATERMARK))

    def test_the_window_is_aligned_to_the_round_so_retries_agree(self):
        self.write_artifact(ORIGINAL)
        early, _ = self.run_tick(now=timestamp('2026-08-05T12:04:59Z'))
        late, _ = self.run_tick(now=FIRST)
        self.assertEqual(early['window'], window(WATERMARK))
        self.assertEqual(late['window'], WINDOW)

    def test_a_cursor_from_another_tree_is_refused_rather_than_re_baselined(self):
        self.write_artifact(ORIGINAL)
        self.run_tick()
        other = self.config(root=str(self.root / 'second-tree'))
        with self.assertRaises(ValueError):
            configdrift.tick(self.index, other, self.cursor, Deliverer(self.store, now=LATER),
                             now=LATER, source=SOURCE)

    def test_two_artifacts_on_one_resource_are_evaluated_apart(self):
        config = self.config(resources=[
            {'resource_id': RESOURCE, 'name': 'running-config', 'rule_id': RULE},
            {'resource_id': RESOURCE, 'name': 'startup-config', 'rule_id': 'drift.router-startup'}])
        self.write_artifact(ORIGINAL)
        self.write_artifact(ORIGINAL, name='startup-config')
        self.run_tick(config=config)
        self.write_artifact(EDITED, name='startup-config')
        _, delivered = self.run_tick(now=LATER, config=config,
                                     deliverer=Deliverer(self.store, now=LATER))
        self.assertEqual([item['rule_id'] for item in delivered.events], ['drift.router-startup'])

    def test_the_cursor_retains_the_text_the_diff_is_built_from(self):
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.assertEqual(self.remembered()['text'], ORIGINAL)

    def test_the_round_summary_carries_every_field_the_worker_log_line_is_built_from(self):
        """`main` reads these keys off the summary; a missing one is a WARNING on every round.

        The first version of this test caught exactly that: the tick line wanted an `events` count the
        summary did not carry, and the only symptom would have been a worker that logged a failure
        forever while delivering everything correctly.
        """
        self.write_artifact(ORIGINAL)
        summary, _ = self.run_tick()
        self.assertEqual(set(summary), {'result', 'window', 'events', 'replayed', 'evaluations', 'changed',
                                        'baselined', 'unreadable', 'acknowledged'})
        self.assertEqual(summary['events'], [])
        self.assertEqual(summary['replayed'], 0, 'a round that owed nothing counted a replay anyway')
        self.assertEqual([set(row) for row in summary['evaluations']],
                         [{'resource_id', 'name', 'rule_id', 'previous_sha256', 'current_sha256',
                           'changed', 'diff', 'diff_lines', 'error', 'error_class', 'ack'}])

    def test_the_cursor_file_holds_config_text_so_it_is_written_private(self):
        if os.name == 'nt':
            self.skipTest('this asserts POSIX mode bits, which Windows does not store')
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.assertEqual(self.cursor.stat().st_mode & 0o077, 0)


class CursorDocumentTests(Fixture):
    """A cursor is remembered state, so a damaged or foreign one is refused, never trusted."""

    def load(self, document: object) -> None:
        path = self.write_json(document, 'cursor.json')
        configdrift.load_cursor(path, self.config())

    def test_a_missing_cursor_is_an_empty_baseline_and_not_a_failure(self):
        config = self.config()
        self.assertEqual(configdrift.load_cursor(self.root / 'none.json', config),
                         {'schema_version': 1, 'binding': configdrift.cursor_binding(config),
                          'seen': {}})

    def test_documents_that_are_not_a_cursor_are_refused(self) -> None:
        binding = configdrift.cursor_binding(self.config())
        broken: list = [
            ('not json', 'a cursor that is not JSON'),
            ({'schema_version': 2, 'binding': binding, 'seen': {}}, 'a cursor from a newer producer'),
            ({'binding': binding, 'seen': {}}, 'a cursor with no schema version'),
            ({'schema_version': 1, 'binding': 'f' * 64, 'seen': {}}, 'a cursor from another tree'),
            ({'schema_version': 1, 'binding': binding, 'seen': 'not-a-map'}, 'a cursor with junk seen'),
            ({'schema_version': 1, 'binding': binding,
              'seen': {f'{RESOURCE}/running-config': {'sha256': 'nope', 'text': ORIGINAL,
                                                      'unreadable': False}}}, 'a digest that is not 64 hex'),
            ({'schema_version': 1, 'binding': binding,
              'seen': {f'{RESOURCE}/running-config': {'sha256': sha256(ORIGINAL), 'text': None,
                                                      'unreadable': False}}}, 'a digest with no text'),
            ({'schema_version': 1, 'binding': binding,
              'seen': {f'{RESOURCE}/running-config': {'sha256': None, 'text': None,
                                                      'unreadable': False}}}, 'a readable digestless entry'),
            ({'schema_version': 1, 'binding': binding,
              'seen': {f'{RESOURCE}/running-config': {'sha256': sha256(ORIGINAL),
                                                      'text': 'x' * 100_000,
                                                      'unreadable': False}}},
             'more retained text than the read ceiling allows'),
        ]
        for document, reason in broken:
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                self.load(document)

    def test_a_digestless_entry_is_legal_only_while_that_artifact_is_unreadable(self):
        binding = configdrift.cursor_binding(self.config())
        self.load({'schema_version': 1, 'binding': binding,
                   'seen': {f'{RESOURCE}/running-config': {'sha256': None, 'text': None,
                                                           'unreadable': True}}})


class WorkerLoopTests(Fixture):
    """One round of `main`: the environment it reads, the client it builds, the cursor it advances."""

    def environment(self) -> dict:
        """The whole set a deployed producer needs, with a token long enough to be accepted."""
        return {configdrift.CONFIG_ENVIRONMENT: str(self.write_json(self.document())),
                configdrift.SOURCE_ENVIRONMENT: SOURCE,
                'LO_INDEX_PATH': str(self.index),
                'LO_PLATFORM_URL': 'https://platform.invalid',
                'LO_PRODUCER_TOKEN': 'a-producer-token-of-at-least-twenty-four-characters'}

    def test_one_round_posts_the_change_logs_once_and_advances_the_cursor(self):
        self.write_artifact(ORIGINAL)
        self.run_tick()                       # the baseline round, taken through the same code path
        self.write_artifact(EDITED)
        posted: list[tuple[str, str, dict]] = []
        built: dict = {}
        store = self.store

        class Platform:
            """Stands in for `http.JsonClient`: no socket, and intake answers with the real store."""

            def __init__(self, base: str, token: str, *, allow_http: bool = False) -> None:
                built['endpoint'], built['allow_http'] = base, allow_http

            def request(self, method: str, path: str, payload: dict) -> tuple[int, dict]:
                posted.append((method, path, dict(payload)))
                return 200, store.intake(payload, PRODUCER)

        with mock.patch.dict('os.environ', self.environment(), clear=True), \
                mock.patch.object(configdrift, 'JsonClient', Platform), \
                mock.patch.object(configdrift.time, 'sleep', side_effect=StopIteration), \
                self.assertLogs('local_observe.platform.configdrift', 'INFO') as captured:
            with self.assertRaises(StopIteration):
                configdrift.main()
        self.assertEqual(built['endpoint'], 'https://platform.invalid')
        self.assertFalse(built['allow_http'])
        self.assertEqual([(method, path) for method, path, _ in posted], [('POST', '/v1/events')])
        finding = posted[0][2]
        self.assertEqual(finding['kind'], 'drift')
        self.assertEqual(finding['evidence'][0]['parameters']['artifact_sha256'], sha256(EDITED))
        self.assertEqual(self.remembered()['sha256'], sha256(EDITED))
        ticked = [record for record in captured.records if record.msg == 'Config-drift tick finished']
        self.assertEqual(len(ticked), 1)
        self.assertEqual((ticked[0].result, ticked[0].events, ticked[0].changed), ('delivered', 1, 1))


class PlatformCommandTests(Fixture):
    """`lo-platform drift` is the same round with a database on the other side of the seam."""

    def run_cli(self, *argv: str) -> tuple[int, dict, str]:
        original = list(sys.argv)
        sys.argv = ['lo-platform', '--database', str(self.root / 'cli-state.db'), *argv]
        printed, logged = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(logged):
                code = cli.main()
        finally:
            sys.argv = original
        return code, json.loads(printed.getvalue()), logged.getvalue()

    def drift(self, *extra: str, now: dt.datetime = NOW, root: str | None = None,
              name: str = 'drift.json') -> tuple[int, dict, str]:
        config = self.write_json(self.document(root=root) if root else self.document(), name)
        return self.run_cli('drift', '--config', str(config), '--index', str(self.index),
                            '--source', SOURCE, '--now', utc_text(now), *extra)

    def test_the_subcommand_baselines_and_then_reports_one_change(self):
        self.write_artifact(ORIGINAL)
        code, result, _ = self.drift()
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'idle')
        self.assertEqual(result['events'], [])
        self.assertEqual(result['evaluations'][0]['current_sha256'], sha256(ORIGINAL))
        self.assertNotIn('diff', result['evaluations'][0], 'the diff is printed when it was not asked for')
        self.write_artifact(EDITED)
        code, result, _ = self.drift('--show-diff', now=LATER, name='drift-second.json')
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'delivered')
        self.assertEqual(result['events'][0]['status'], 'accepted')
        self.assertEqual(result['events'][0]['transition'], 'opened')
        self.assertIn('+snmp-server community private', result['evaluations'][0]['diff'])
        self.assertEqual([item['kind'] for item in self.stored_events(self.root / 'cli-state.db')],
                         ['drift'])

    def test_a_missing_index_is_a_json_error_and_not_a_traceback(self):
        self.write_artifact(ORIGINAL)
        original = list(sys.argv)
        sys.argv = ['lo-platform', '--database', str(self.root / 'cli-state.db'), 'drift',
                    '--config', str(self.write_json(self.document())), '--index',
                    str(self.root / 'absent' / 'inventory.db'), '--source', SOURCE]
        printed, logged = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(logged):
                code = cli.main()
        finally:
            sys.argv = original
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(printed.getvalue())['status'], 'error')
        self.assertNotIn('Traceback', printed.getvalue())

    def test_a_missing_snapshot_tree_files_coverage_into_the_database(self):
        code, result, _ = self.drift(root=str(self.root / 'gone'))
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'unreadable')
        self.assertEqual(self.stored_events(self.root / 'cli-state.db')[0]['kind'], 'coverage')

    def test_the_subcommand_is_registered_in_the_parser(self):
        """`drift` is a known command, so argparse asks for its own arguments rather than its name.

        An unregistered word dies as "invalid choice: 'drift'"; a registered one missing its flags
        dies naming the flags. Both exit 2, so the complaint is the only thing that tells them apart,
        and this is the check that fails the day the registration is dropped.
        """
        code, message = self.expect_argparse_error('drift')
        self.assertEqual(code, 2)
        self.assertNotIn("invalid choice: 'drift'", message)
        self.assertIn('--config', message)

    def expect_argparse_error(self, *argv: str) -> tuple[int, str]:
        """Run one knowingly-incomplete command line; return argparse's code and its complaint."""
        original = list(sys.argv)
        sys.argv = ['lo-platform', '--database', str(self.root / 'cli-state.db'), *argv]
        logged = io.StringIO()
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(logged):
                with self.assertRaises(SystemExit) as raised:
                    cli.main()
        finally:
            sys.argv = original
        return raised.exception.code, logged.getvalue()


class VocabularyTests(unittest.TestCase):
    """`drift` the kind, `drift` the inventory subcommand and `drift` the content key: three things."""

    def test_the_producer_emits_a_kind_the_platform_admits(self):
        self.assertIn('drift', EVENT_KINDS)
        entry = {'resource_id': RESOURCE, 'name': 'running-config', 'rule_id': RULE}
        comparison = configdrift.Comparison(sha256(ORIGINAL), sha256(EDITED), '')
        finding = configdrift.drift_finding(SOURCE, entry, WINDOW, comparison)
        self.assertEqual(finding['kind'], 'drift')
        self.assertEqual(finding['status'], 'firing')
        self.assertEqual(finding['evidence'][0]['query_type'], 'observed-snapshot')
        self.assertEqual(finding['evidence'][0]['parameters']['artifact_sha256'], sha256(EDITED))


class AcknowledgementFixture(Fixture):
    """The shared scratch, plus the operator's acknowledgement tree and the records filed in it.

    Nothing here goes through the command-line tool on purpose: these classes test the **reader** and
    the **resolve rule**, and `tests/test_drift_ack.py` tests the writer. The one thing they must agree
    on is the bytes, so a record is written as `validate_acknowledgement` normalises it — the same
    canonical form `drift_ack.write_acknowledgement` installs — and its identity is the digest of that
    normalised record, not of the file.
    """

    ACKED_AT = timestamp('2026-08-05T12:07:00Z')

    def setUp(self) -> None:
        super().setUp()
        self.ack_root = self.root / 'acknowledgements'

    def record(self, artifact_sha256: str, **overrides) -> dict:
        """One valid acknowledgement document as an operator would file it, with *overrides* merged."""
        document: dict = {'schema_version': 1, 'resource_id': RESOURCE, 'name': 'running-config',
                          'rule_id': RULE, 'artifact_sha256': artifact_sha256,
                          'actor': 'operator-one', 'reason': 'checked against the change ticket',
                          'at': utc_text(self.ACKED_AT)}
        document.update(overrides)
        return document

    def ack_config(self, **overrides) -> dict:
        """The default configuration with the acknowledgement path switched on."""
        return self.config(acknowledgements=str(self.ack_root), **overrides)

    def file_ack(self, artifact_sha256: str, *, raw: str | None = None, **overrides) -> str:
        """Put one record where the producer will look for it; return the identity it must remember.

        *raw* writes the file verbatim instead of the normalised record, which is how the refusal tests
        hand the reader garbage it must not trust.
        """
        document = configdrift.validate_acknowledgement(self.record(artifact_sha256, **overrides))
        path = configdrift.acknowledgement_path(self.ack_root, document['resource_id'], document['name'])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw if raw is not None else json.dumps(document, sort_keys=True),
                        encoding='utf-8', newline='')
        return digest(document)

    def incident_status(self, incident_id: str) -> str:
        """Read one incident row back out of the platform database the rounds wrote to."""
        with contextlib.closing(sqlite3.connect(self.root / 'state.db')) as connection:
            row = connection.execute('SELECT status FROM incidents WHERE id=?', (incident_id,)).fetchone()
        self.assertIsNotNone(row, 'the incident row the round opened is gone')
        return row[0]

    def deliveries(self) -> list[tuple[str, str]]:
        """Every queued notification, oldest first, as `(transition, incident_id)`.

        Both halves of a transition queue a delivery — an `opened` and a `resolved` — so this is the list
        an operator's channel actually received, and the shape drift resolution exists to fix: while an incident
        could not close, a second change queued nothing at all and was delivered to nobody.
        """
        with contextlib.closing(sqlite3.connect(self.root / 'state.db')) as connection:
            rows = connection.execute('SELECT payload FROM outbox ORDER BY sequence').fetchall()
        return [(json.loads(row[0])['transition'], json.loads(row[0])['incident_id']) for row in rows]


class AcknowledgementReaderTests(AcknowledgementFixture):
    """The record is read or refused: absence is quiet, damage is loud, and nothing in between."""

    def test_an_absent_record_is_an_answer_and_not_a_failure(self):
        self.assertIsNone(configdrift.read_acknowledgement(self.ack_root, RESOURCE, 'running-config'))
        self.write_artifact(ORIGINAL)                        # the tree exists; nothing was acknowledged
        self.assertIsNone(configdrift.read_acknowledgement(self.ack_root, RESOURCE, 'running-config'))

    def test_the_record_that_is_filed_reads_back_with_its_identity(self):
        identity = self.file_ack(sha256(ORIGINAL))
        document, read = configdrift.read_acknowledgement(self.ack_root, RESOURCE, 'running-config')
        self.assertEqual(read, identity)
        self.assertEqual((document['resource_id'], document['name'], document['rule_id']),
                         (RESOURCE, 'running-config', RULE))
        self.assertEqual(document['artifact_sha256'], sha256(ORIGINAL))

    def test_the_identity_is_the_record_not_the_bytes_written(self):
        """Hand-typed whitespace cannot split one promise into two acknowledgements."""
        document = configdrift.validate_acknowledgement(self.record(sha256(ORIGINAL)))
        self.file_ack(sha256(ORIGINAL), raw=json.dumps(document, indent=2, sort_keys=False))
        _, read = configdrift.read_acknowledgement(self.ack_root, RESOURCE, 'running-config')
        self.assertEqual(read, digest(document))

    def test_the_same_digest_acknowledged_again_is_a_new_record(self):
        """A re-acknowledgement is what closes a *second* incident, so it must not reuse the old id."""
        first = configdrift.validate_acknowledgement(self.record(sha256(ORIGINAL)))
        second = configdrift.validate_acknowledgement(self.record(sha256(ORIGINAL), at=utc_text(FOURTH)))
        self.assertEqual(first['artifact_sha256'], second['artifact_sha256'])
        self.assertNotEqual(digest(first), digest(second))

    def test_a_record_named_by_a_path_that_escapes_the_tree_never_exists(self):
        """`name` is the one component an operator types freely; the ack path holds it to the same rule."""
        with self.assertRaises(ValueError):
            configdrift.validate_acknowledgement(self.record(sha256(ORIGINAL), name='../escape'))
        self.assertEqual(configdrift.acknowledgement_path(self.ack_root, RESOURCE, 'running-config'),
                         self.ack_root / RESOURCE / 'running-config.json')

    def test_records_that_are_not_acknowledgements_are_refused(self) -> None:
        good = self.record(sha256(ORIGINAL))
        broken: list = [
            ('a document that is not an object', 'this is not json'),
            ('a field missing', {key: value for key, value in good.items() if key != 'reason'}),
            ('an unknown field', {**good, 'ticket': 'ops-1'}),
            ('a schema version this reader does not know', {**good, 'schema_version': 2}),
            ('a boolean schema version', {**good, 'schema_version': True}),
            ('a resource_id that is not a canonical UUID', {**good, 'resource_id': 'router-01'}),
            ('a name that leaves the tree', {**good, 'name': '../escape'}),
            ('a name with a separator', {**good, 'name': 'a/b'}),
            ('a name a tool reads as a flag', {**good, 'name': '-flag'}),
            ('a rule_id outside the bounded pattern', {**good, 'rule_id': 'x' * 129}),
            ('an actor that is not a bounded label', {**good, 'actor': 'a name with spaces'}),
            ('a digest that is not a digest', {**good, 'artifact_sha256': 'nope'}),
            ('a digest in the wrong case', {**good, 'artifact_sha256': sha256(ORIGINAL).upper()}),
            ('a naive at', {**good, 'at': '2026-08-05T12:00:00'}),
            ('no reason', {**good, 'reason': ''}),
            ('a reason past the sentence bound', {**good, 'reason': 'y' * 257}),
            ('a reason holding a control character', {**good, 'reason': 'line one\nline two'}),
        ]
        for position, (reason, document) in enumerate(broken):
            with self.subTest(refusal=reason), self.assertRaises(ValueError):
                configdrift.validate_acknowledgement(document)
            with self.subTest(refusal=f'{reason} on disk'):
                self.file_ack(sha256(ORIGINAL),
                              raw=json.dumps(document) if isinstance(document, dict)
                              else f'damaged-{position}')
                with self.assertRaises(ValueError):
                    configdrift.read_acknowledgement(self.ack_root, RESOURCE, 'running-config')

    def test_an_oversized_record_is_refused(self):
        self.file_ack(sha256(ORIGINAL), raw=json.dumps({**self.record(sha256(ORIGINAL)),
                                                        'reason': 'y' * configdrift.MAX_ACK_BYTES}))
        with self.assertRaises(ValueError):
            configdrift.read_acknowledgement(self.ack_root, RESOURCE, 'running-config')

    def test_text_that_is_not_json_is_refused_as_its_own_code(self):
        self.file_ack(sha256(ORIGINAL), raw='{ "resource_id": ')
        with self.assertRaises(ValueError):
            configdrift.read_acknowledgement(self.ack_root, RESOURCE, 'running-config')

    def test_bytes_that_are_not_utf8_keep_their_own_code(self):
        """Rewriting the decode failure as a ValueError would report it as `ack_invalid` instead."""
        path = configdrift.acknowledgement_path(self.ack_root, RESOURCE, 'running-config')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'\xff\xfe nothing here')
        with self.assertRaises(UnicodeDecodeError):
            configdrift.read_acknowledgement(self.ack_root, RESOURCE, 'running-config')

    def test_a_symlinked_record_is_refused(self):
        outside = self.root / 'elsewhere.json'
        outside.write_text(json.dumps(self.record(sha256(ORIGINAL))), encoding='utf-8')
        path = configdrift.acknowledgement_path(self.ack_root, RESOURCE, 'running-config')
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest('this platform does not let the test create a symlink')
        with self.assertRaises(ValueError):
            configdrift.read_acknowledgement(self.ack_root, RESOURCE, 'running-config')


class AcknowledgementResolveTests(AcknowledgementFixture):
    """The resolve rule itself: what closes an incident, and the six things that do not."""

    def test_an_acknowledged_change_closes_the_incident_and_the_rule_stays_configured(self):
        """drift resolution's acceptance test: ack the reported change, and the incident closes with the rule in place.

        The read-back is the point, not the event: an operator who acknowledged a change must be able to
        see the incident row say `resolved`, and must still find the rule configured and tracked so the
        next change to the same artifact is caught. Nothing here disables the thing that caught it.
        """
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)                                   # a baseline files nothing
        self.write_artifact(EDITED)
        opened_summary, opened = self.run_tick(now=LATER, config=config)
        self.assertEqual(opened_summary['result'], 'delivered')
        self.assertEqual(opened.receipts[0]['transition'], 'opened')
        incident_id = opened.receipts[0]['incident_id']
        record = self.file_ack(sha256(EDITED))

        summary, closed = self.run_tick(now=THIRD, config=config)
        self.assertEqual([(item['kind'], item['status']) for item in closed.events],
                         [('drift', 'resolved')], 'one round, one event on the drift condition')
        finding = closed.events[0]
        self.assertEqual((finding['rule_id'], finding['resource_id'], finding['source']),
                         (RULE, RESOURCE, SOURCE))
        self.assertEqual(finding['evidence'][0]['parameters'],
                         {'rule_id': RULE, 'artifact_sha256': sha256(EDITED)})
        self.assertEqual(finding['window'], summary['window'])
        self.assertEqual(finding['window'], window(timestamp('2026-08-05T12:10:00Z')),
                         'the resolve carries the window it was judged in, not the one it was filed in')
        self.assertEqual(closed.receipts[0]['transition'], 'resolved')
        self.assertEqual(closed.receipts[0]['incident_id'], incident_id)
        self.assertEqual(summary['result'], 'delivered')
        self.assertEqual(summary['acknowledged'], 1)
        self.assertEqual(summary['evaluations'][0]['ack'], 'applied')
        self.assertEqual(self.incident_status(incident_id), 'resolved')
        self.assertEqual(config['resources'], [{'resource_id': RESOURCE, 'name': 'running-config',
                                                'rule_id': RULE}])
        self.assertEqual(self.remembered(config)['sha256'], sha256(EDITED))
        self.assertEqual(self.remembered(config)['ack_applied'], record)

    def test_a_stale_acknowledgement_never_closes_an_incident_and_never_hides_the_change(self):
        """An ack names one exact digest: once the bytes move again it is inert, and the change is filed."""
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        _, opened = self.run_tick(now=LATER, config=config)
        incident_id = opened.receipts[0]['incident_id']
        self.file_ack(sha256(EDITED))

        self.write_artifact(REPLACED)                                  # a second change, after the ack
        summary, delivered = self.run_tick(now=THIRD, config=config)
        self.assertEqual([(item['kind'], item['status']) for item in delivered.events],
                         [('drift', 'firing')], 'the new change was hidden behind a spent acknowledgement')
        self.assertEqual(delivered.events[0]['evidence'][0]['parameters']['artifact_sha256'],
                         sha256(REPLACED))
        self.assertIsNone(delivered.receipts[0]['transition'])
        self.assertEqual(summary['evaluations'][0]['ack'], 'stale')
        self.assertEqual(summary['acknowledged'], 0)
        self.assertEqual(self.incident_status(incident_id), 'open')
        self.assertNotIn('ack_applied', self.remembered(config))

    def test_an_acknowledgement_of_the_change_it_names_waits_for_the_next_round(self):
        """A firing event and a resolve share one `source_event_id` in one window, so they never coexist."""
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        self.file_ack(sha256(EDITED))                                  # filed before the round sees it
        summary, delivered = self.run_tick(now=LATER, config=config)
        self.assertEqual([(item['kind'], item['status']) for item in delivered.events],
                         [('drift', 'firing')])
        self.assertEqual(summary['evaluations'][0]['ack'], 'deferred')
        self.assertNotIn('ack_applied', self.remembered(config))

        second, applied = self.run_tick(now=THIRD, config=config)
        self.assertEqual([(item['kind'], item['status']) for item in applied.events],
                         [('drift', 'resolved')])
        self.assertEqual(applied.receipts[0]['transition'], 'resolved')
        self.assertEqual(second['evaluations'][0]['ack'], 'applied')

    def test_one_acknowledgement_is_applied_once(self):
        """A spent record is `already`: re-emitting a resolve every round would speak over the close."""
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        self.file_ack(sha256(EDITED))
        self.run_tick(now=LATER, config=config)                        # deferred
        self.run_tick(now=THIRD, config=config)                        # applied
        summary, quiet = self.run_tick(now=FOURTH, config=config)
        self.assertEqual(quiet.events, [], 'a spent acknowledgement re-resolved the condition')
        self.assertEqual(summary['evaluations'][0]['ack'], 'already')
        self.assertEqual(summary['result'], 'idle')
        self.assertEqual(summary['acknowledged'], 0)

    def test_a_change_after_an_acknowledgement_opens_a_second_incident_and_queues_a_second_delivery(self):
        """The blind spot this card exists for: while one incident stayed open, nobody was told twice.

        The close is what restores notification, because `conditions.incident_id` goes NULL with it, so
        the next digest move is a fresh `opened` transition with its own outbox row. Before this card the
        second change only moved `updated_at`, and no delivery was ever queued for it.
        """
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        _, first = self.run_tick(now=LATER, config=config)
        self.file_ack(sha256(EDITED))
        self.run_tick(now=THIRD, config=config)                        # the close
        opened_id = first.receipts[0]['incident_id']
        self.assertEqual(self.deliveries(), [('opened', opened_id), ('resolved', opened_id)])

        self.write_artifact(REPLACED)
        summary, second = self.run_tick(now=FOURTH, config=config)
        self.assertEqual(second.receipts[0]['transition'], 'opened')
        self.assertNotEqual(second.receipts[0]['incident_id'], opened_id)
        self.assertEqual(self.deliveries(), [('opened', opened_id), ('resolved', opened_id),
                                             ('opened', second.receipts[0]['incident_id'])],
                         'the second change reached nobody')
        self.assertEqual(summary['evaluations'][0]['ack'], 'stale')
        self.assertEqual(self.incident_status(opened_id), 'resolved')
        self.assertEqual(self.incident_status(second.receipts[0]['incident_id']), 'open')

    def test_an_acknowledgement_for_an_unreadable_artifact_closes_nothing(self):
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        _, opened = self.run_tick(now=LATER, config=config)
        incident_id = opened.receipts[0]['incident_id']
        self.file_ack(sha256(EDITED))
        self.artifact.unlink()                                         # filed, then the artifact is gone

        summary, delivered = self.run_tick(now=THIRD, config=config)
        self.assertEqual([item['kind'] for item in delivered.events], ['coverage'])
        self.assertEqual(delivered.events[0]['rule_id'], RULE + '.coverage')
        self.assertEqual(summary['evaluations'][0]['ack'], 'unreadable')
        self.assertIn(summary['evaluations'][0]['ack'], configdrift.ACK_STATES)
        self.assertEqual(self.incident_status(incident_id), 'open')

    def test_a_malformed_acknowledgement_is_refused_without_a_coverage_claim(self):
        """A broken operator instruction is not blindness about the artifact, so it never files coverage."""
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        _, opened = self.run_tick(now=LATER, config=config)
        incident_id = opened.receipts[0]['incident_id']
        self.file_ack(sha256(EDITED), raw='not json at all')

        with self.assertLogs('local_observe.platform.configdrift', 'WARNING') as captured:
            summary, delivered = self.run_tick(now=THIRD, config=config)
        refused = [record for record in captured.records
                   if record.msg == 'Drift acknowledgement refused']
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0].code, 'ack_invalid')
        self.assertEqual(refused[0].artifact, f'{RESOURCE}/running-config')
        self.assertEqual(delivered.events, [], 'a refused acknowledgement changed what the round filed')
        self.assertEqual(summary['result'], 'idle')
        self.assertEqual(summary['evaluations'][0]['ack'], 'refused')
        self.assertEqual(summary['evaluations'][0]['error'], None)
        self.assertEqual(self.incident_status(incident_id), 'open')

    def test_bytes_that_are_not_utf8_are_refused_under_their_own_code(self):
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        self.run_tick(now=LATER, config=config)
        path = configdrift.acknowledgement_path(self.ack_root, RESOURCE, 'running-config')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'\xff\xfe not a record')
        with self.assertLogs('local_observe.platform.configdrift', 'WARNING') as captured:
            summary, delivered = self.run_tick(now=THIRD, config=config)
        codes = [record.code for record in captured.records
                 if record.msg == 'Drift acknowledgement refused']
        self.assertEqual(codes, ['ack_not_utf8'])
        self.assertEqual(delivered.events, [])
        self.assertEqual(summary['evaluations'][0]['ack'], 'refused')

    def test_a_rule_id_that_no_longer_matches_the_configuration_is_refused(self):
        """A record must name the rule that watches this artifact now, or it closes nothing."""
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        _, opened = self.run_tick(now=LATER, config=config)
        incident_id = opened.receipts[0]['incident_id']
        self.file_ack(sha256(EDITED), rule_id='drift.some-other-rule')

        with self.assertLogs('local_observe.platform.configdrift', 'WARNING') as captured:
            summary, delivered = self.run_tick(now=THIRD, config=config)
        codes = [record.code for record in captured.records
                 if record.msg == 'Drift acknowledgement refused']
        self.assertEqual(codes, ['ack_rule_mismatch'])
        self.assertEqual(delivered.events, [])
        self.assertEqual(summary['evaluations'][0]['ack'], 'refused')
        self.assertEqual(self.incident_status(incident_id), 'open')

    def test_a_record_naming_another_artifact_is_refused(self):
        """The body must name the artifact whose path it sits at; a copy moved between directories lies."""
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        _, opened = self.run_tick(now=LATER, config=config)
        incident_id = opened.receipts[0]['incident_id']
        self.file_ack(sha256(EDITED), raw=json.dumps(self.record(sha256(EDITED), name='startup-config')))

        with self.assertLogs('local_observe.platform.configdrift', 'WARNING') as captured:
            summary, delivered = self.run_tick(now=THIRD, config=config)
        codes = [record.code for record in captured.records
                 if record.msg == 'Drift acknowledgement refused']
        self.assertEqual(codes, ['ack_rule_mismatch'])
        self.assertEqual(delivered.events, [])
        self.assertEqual(summary['evaluations'][0]['ack'], 'refused')
        self.assertEqual(self.incident_status(incident_id), 'open')

    def test_the_acknowledgement_path_is_off_when_the_config_names_no_directory(self):
        """No `acknowledgements` key: every record is invisible, and the round is exactly as it was."""
        config = self.config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        _, opened = self.run_tick(now=LATER, config=config)
        incident_id = opened.receipts[0]['incident_id']
        self.file_ack(sha256(EDITED))                                  # filed where the config does not look
        summary, delivered = self.run_tick(now=THIRD, config=config)
        self.assertEqual(delivered.events, [])
        self.assertEqual(summary['evaluations'][0]['ack'], 'none')
        self.assertEqual(summary['acknowledged'], 0)
        self.assertEqual(self.incident_status(incident_id), 'open')
        self.assertNotIn('ack_applied', self.remembered(config))


class AcknowledgementCursorTests(AcknowledgementFixture):
    """The cursor's one new field: it survives every rebuild, and turning it on costs no baseline."""

    def test_turning_acknowledgements_on_does_not_invalidate_an_existing_cursor(self):
        """The binding is about which bytes are watched; where an operator files a record is not that.

        A binding that moved with `acknowledgements` would have every existing cursor answered with
        'remove it to re-baseline' — a round that fails forever until an operator deletes the file and
        loses every stored digest — so this is the trap the docstring warns about, pinned.
        """
        self.write_artifact(ORIGINAL)
        self.run_tick()                                                # written before the key existed
        config = self.ack_config()
        self.assertEqual(configdrift.cursor_binding(config), configdrift.cursor_binding(self.config()))
        summary, delivered = self.run_tick(now=LATER, config=config)
        self.assertEqual(self.remembered(config)['sha256'], sha256(ORIGINAL))
        self.assertEqual(delivered.events, [])
        self.assertEqual(summary['result'], 'idle')

    def test_an_entry_holds_the_ack_marker_only_once_one_was_applied(self):
        """An artifact nobody acknowledged keeps today's exact three-key entry."""
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.assertEqual(set(self.remembered(config)), {'sha256', 'text', 'unreadable'})
        self.write_artifact(EDITED)
        self.run_tick(now=LATER, config=config)
        self.assertEqual(set(self.remembered(config)), {'sha256', 'text', 'unreadable'})
        self.file_ack(sha256(EDITED))
        self.run_tick(now=THIRD, config=config)
        self.assertEqual(set(self.remembered(config)), {'sha256', 'text', 'unreadable', 'ack_applied'})

    def test_the_marker_survives_a_round_that_could_not_read_the_artifact(self):
        """Rebuilding an entry from scratch must not forget a spent acknowledgement, gap included."""
        config = self.ack_config()
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        record = self.file_ack(sha256(EDITED))
        self.run_tick(now=LATER, config=config)                        # deferred: the round files the change
        applied, closed = self.run_tick(now=THIRD, config=config)
        self.assertEqual(closed.receipts[0]['transition'], 'resolved')
        self.assertEqual(applied['acknowledged'], 1)
        self.assertEqual(self.remembered(config)['ack_applied'], record)
        self.remove_tree()                                             # a blind round rebuilds the entry
        blind, _ = self.run_tick(now=FOURTH, config=config)
        self.assertEqual(blind['evaluations'][0]['ack'], 'unreadable')
        self.assertEqual(self.remembered(config)['ack_applied'], record)
        self.assertTrue(self.remembered(config)['unreadable'])

    def test_a_marker_that_is_not_a_digest_is_refused(self):
        binding = configdrift.cursor_binding(self.ack_config())
        document = {'schema_version': 1, 'binding': binding,
                    'seen': {f'{RESOURCE}/running-config': {'sha256': sha256(ORIGINAL), 'text': ORIGINAL,
                                                            'unreadable': False,
                                                            'ack_applied': 'not-a-digest'}}}
        with self.assertRaises(ValueError):
            configdrift.load_cursor(self.write_json(document, 'cursor.json'), self.ack_config())

    def test_a_hand_written_marker_that_is_a_digest_is_accepted(self):
        """A marker is a spend record, not a secret: 64 hex is what `load_cursor` asks of it."""
        binding = configdrift.cursor_binding(self.ack_config())
        seen = {f'{RESOURCE}/running-config': {'sha256': sha256(ORIGINAL), 'text': ORIGINAL,
                                               'unreadable': False, 'ack_applied': 'a' * 64}}
        path = self.write_json({'schema_version': 1, 'binding': binding, 'seen': seen}, 'cursor.json')
        self.assertEqual(configdrift.load_cursor(path, self.ack_config())['seen'], seen)


if __name__ == '__main__':
    unittest.main()

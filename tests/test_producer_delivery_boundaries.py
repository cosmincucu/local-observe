"""Delivery exceptions and repeated windows cannot erase an already committed transition."""
import datetime as dt
import json
import unittest
from unittest.mock import patch

from local_observe.http import TransportError
from local_observe.platform import configdrift, pathcheck
from local_observe.platform.state import Actor
from test_correlation import GraphFixture, NOW as DRIFT_NOW, identifier
from test_pathcheck import Fixture, API, ROUTER, NOW, WATERMARK, PRODUCER, SOURCE


class DeliveryBoundaryTests(unittest.TestCase):
    def test_malformed_completed_windows_are_refused_before_replay(self):
        fixture = self.path_fixture()
        configs = [(pathcheck, fixture.config(protocols=['icmp']), {'open': None, 'routes': {}}),
                   (configdrift, {'root': str(fixture.root), 'resources': []}, {'seen': {}})]
        for module, config, fields in configs:
            for malformed in (None, False, 17, {}, [], '', 'not-a-time'):
                with self.subTest(producer=module.__name__, malformed=malformed):
                    document = {'schema_version': 1, 'binding': module.cursor_binding(config),
                                **fields, 'settled_end': malformed}
                    fixture.cursor.write_text(json.dumps(document), encoding='utf-8')
                    with self.assertRaises(ValueError):
                        module.load_cursor(fixture.cursor, config)

    def path_fixture(self):
        fixture = Fixture('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_a_later_refusal_keeps_the_whole_batch_after_an_earlier_commit(self):
        for commit_second in (False, True):
            with self.subTest(commit_second=commit_second):
                fixture = self.path_fixture()
                config = fixture.config(protocols=['icmp'])
                moment = NOW
                def deliver(item):
                    return fixture.store.intake(item, PRODUCER, now=moment)
                fixture.write_report([{'target': API, 'ok': False}, {'target': ROUTER, 'ok': True}])
                pathcheck.tick(fixture.index, config, fixture.cursor, deliver, now=moment, source=SOURCE)
                moment += dt.timedelta(minutes=5)
                fixture.write_report([], observed_at=WATERMARK + dt.timedelta(minutes=5))
                attempts = []
                def refuse_second(item):
                    attempts.append(item)
                    if len(attempts) == 2:
                        if commit_second:
                            deliver(item)
                        raise ValueError('Synthetic refusal or undecodable response')
                    deliver(item)
                with self.assertRaises(ValueError):
                    pathcheck.tick(fixture.index, config, fixture.cursor, refuse_second,
                                   now=moment, source=SOURCE)
                saved = fixture.cursor.read_bytes()
                self.assertEqual(json.loads(saved)['pending']['events'], attempts)
                # The replay also preserves its bytes when a later event fails.
                attempts.clear()
                with self.assertRaises(ValueError):
                    pathcheck.tick(fixture.index, config, fixture.cursor, refuse_second,
                                   now=moment, source=SOURCE)
                self.assertEqual(fixture.cursor.read_bytes(), saved)
                pathcheck.tick(fixture.index, config, fixture.cursor, deliver, now=moment, source=SOURCE)
                moment += dt.timedelta(minutes=5)
                fixture.write_report([{'target': API, 'ok': True}, {'target': ROUTER, 'ok': True}],
                                     observed_at=WATERMARK + dt.timedelta(minutes=10))
                pathcheck.tick(fixture.index, config, fixture.cursor, deliver, now=moment, source=SOURCE)
                self.assertEqual(fixture.store.status()['incidents'], {'resolved': 2})

    def test_pathcheck_does_not_rejudge_a_replayed_window_after_restart(self):
        fixture = self.path_fixture()
        config = fixture.config(protocols=['icmp'])
        moment = NOW
        def deliver(item):
            return fixture.store.intake(item, PRODUCER, now=moment)
        def lose_ack(item):
            deliver(item)
            raise TransportError('Synthetic lost response')
        fixture.write_report([{'target': API, 'ok': False}, {'target': ROUTER, 'ok': True}])
        with self.assertRaises(TransportError):
            pathcheck.tick(fixture.index, config, fixture.cursor, lose_ack, now=moment, source=SOURCE)
        fixture.write_report([{'target': API, 'ok': True}, {'target': ROUTER, 'ok': True}])
        pathcheck.tick(fixture.index, config, fixture.cursor, deliver, now=moment, source=SOURCE)
        for retry_time in (moment, moment - dt.timedelta(minutes=5)):
            with patch.object(pathcheck, 'load_reports', side_effect=AssertionError('Settled window was reread')):
                pathcheck.tick(fixture.index, config, fixture.cursor, deliver, now=retry_time, source=SOURCE)
        self.assertEqual(fixture.store.status()['incidents'], {'open': 1})
        moment += dt.timedelta(minutes=5)
        fixture.write_report([{'target': API, 'ok': True}, {'target': ROUTER, 'ok': True}],
                             observed_at=WATERMARK + dt.timedelta(minutes=5))
        pathcheck.tick(fixture.index, config, fixture.cursor, deliver, now=moment, source=SOURCE)
        self.assertEqual(fixture.store.status()['incidents'], {'resolved': 1})

    def test_drift_does_not_rejudge_a_replayed_window_after_restart(self):
        fixture = GraphFixture('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        store = fixture.store()
        resource = identifier('demo-api')
        tree = fixture.root / 'snapshots'
        artifact = tree / resource / 'running-config'
        artifact.parent.mkdir(parents=True)
        artifact.write_text('feature enabled\n', encoding='utf-8')
        cursor = fixture.root / 'drift.json'
        config = {'root': str(tree), 'resources': [{'resource_id': resource, 'name': 'running-config',
                                                  'rule_id': 'demo.config'}], 'interval_seconds': 60}
        actor = Actor('drift-review', 'producer')
        moment = DRIFT_NOW
        def deliver(item):
            return store.intake(item, actor, now=moment)
        def lose_ack(item):
            deliver(item)
            raise TransportError('Synthetic lost response')
        configdrift.tick(fixture.index_path, config, cursor, deliver, now=moment, source=actor.identity)
        moment += dt.timedelta(minutes=1)
        with patch.object(configdrift, 'read_snapshot', side_effect=OSError('Synthetic source unavailable')):
            with self.assertRaises(TransportError):
                configdrift.tick(fixture.index_path, config, cursor, lose_ack, now=moment, source=actor.identity)
        configdrift.tick(fixture.index_path, config, cursor, deliver, now=moment, source=actor.identity)
        for retry_time in (moment, moment - dt.timedelta(minutes=1)):
            with patch.object(configdrift, 'read_snapshot', side_effect=AssertionError('Settled window was reread')):
                configdrift.tick(fixture.index_path, config, cursor, deliver, now=retry_time, source=actor.identity)
        self.assertEqual(store.status()['incidents'], {'open': 1})
        moment += dt.timedelta(minutes=1)
        configdrift.tick(fixture.index_path, config, cursor, deliver, now=moment, source=actor.identity)
        self.assertEqual(store.status()['incidents'], {'resolved': 1})

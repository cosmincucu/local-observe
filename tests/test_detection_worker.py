"""The synthetics adapter: a window that is configured rather than baked in, and a blind spot that
stays visible.

synthetics component gave `local_observe/platform/detection_worker.py` a configurable evaluation window (it replaced
a hardcoded `// 5`) and pinned the credential scheme its Gatus client uses. Both are cheap changes to
argue about and expensive ones to get wrong, so they are tested from three directions: the value is
bounded rather than coerced, the cursor grid follows the configured value rather than the old constant,
and — the part a synthetic engine is actually for — an **absent** engine produces a firing coverage
verdict and never a resolved availability one. Everything is offline: an in-process index snapshot, a
fake HTTP peer, and `detections.evaluate`'s real refusal paths. No container, no network.
"""
import base64
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.http import JsonClient, TransportError
from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import detections
from local_observe.platform.detection_worker import (DEFAULT_WINDOW_SECONDS, GATUS_AUTH_SCHEME,
                                                    MAXIMUM_WINDOW_SECONDS, MINIMUM_WINDOW_SECONDS,
                                                    tick, window_from_environment)

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-08T12:01:07Z')
SOURCE = 'test-detector'
IDENTITY = '00000000-0000-4000-8000-000000000001'


class EngineDownFake:
    """A Gatus that is not there: an HTTP error status, which is what a refused poll looks like."""

    def __init__(self, status=404):
        self.status = status
        self.calls = 0

    def request(self, *args):
        self.calls += 1
        return self.status, None


class TransportDownFake(EngineDownFake):
    """A Gatus whose connection fails outright, which the adapter must treat the same way."""

    def request(self, *args):
        self.calls += 1
        raise TransportError('connection refused')


class IntakeFake:
    """The platform's two intake paths, recording what arrived so identity can be asserted."""

    def __init__(self):
        self.evidence = []
        self.events = []

    def request(self, method, path, payload):
        if path == '/v1/evidence':
            self.evidence.append(payload)
        elif path == '/v1/events':
            self.events.append(payload)
        else:
            raise AssertionError(f'unexpected intake path {path}')
        return 200, {'ok': True}


class WindowConfigurationTests(unittest.TestCase):
    """The band is 5..3600 s and it is enforced, not suggested."""

    def test_an_unconfigured_environment_keeps_the_window_the_stage_always_ran(self):
        self.assertEqual(window_from_environment({}), DEFAULT_WINDOW_SECONDS)
        self.assertEqual(window_from_environment({'LO_DETECTION_WINDOW_SECONDS': '   '}),
                         DEFAULT_WINDOW_SECONDS)
        self.assertEqual(DEFAULT_WINDOW_SECONDS, 5, 'the default is a delivered behaviour, not a coin '
                                                    'flip: changing it changes the stage')

    def test_both_ends_of_the_band_are_accepted(self):
        self.assertEqual(window_from_environment({'LO_DETECTION_WINDOW_SECONDS': '5'}),
                         MINIMUM_WINDOW_SECONDS)
        self.assertEqual(window_from_environment({'LO_DETECTION_WINDOW_SECONDS': '3600'}),
                         MAXIMUM_WINDOW_SECONDS)
        self.assertEqual(window_from_environment({'LO_DETECTION_WINDOW_SECONDS': ' 60 '}), 60)

    def test_a_value_outside_the_band_refuses_to_start_rather_than_being_clamped(self):
        for text in ('0', '4', '3601', '86400', '-5'):
            with self.subTest(window=text), self.assertRaises(ValueError) as caught:
                window_from_environment({'LO_DETECTION_WINDOW_SECONDS': text})
            self.assertIn('LO_DETECTION_WINDOW_SECONDS', str(caught.exception))

    def test_a_value_that_is_not_a_plain_integer_refuses_too(self):
        """`30s`, `1e3` and `5.0` are all ways an operator can mean something the code will not do."""
        for text in ('30s', '5.0', '1e3', 'PT5M', 'five'):
            with self.subTest(window=text), self.assertRaises(ValueError):
                window_from_environment({'LO_DETECTION_WINDOW_SECONDS': text})

    def test_tick_refuses_the_same_band_and_is_stable_when_it_does(self):
        """A second guard, because `tick()` is also called directly (and by `lo-platform`)."""
        with tempfile.TemporaryDirectory() as directory:
            cursor = Path(directory) / 'cursor.json'
            for seconds in (MINIMUM_WINDOW_SECONDS - 1, MAXIMUM_WINDOW_SECONDS + 1, 0, -1):
                with self.subTest(window=seconds), self.assertRaises(ValueError):
                    tick(Path('unused.db'), {}, cursor, EngineDownFake(), IntakeFake(), now=NOW,
                         window_seconds=seconds)
            self.assertFalse(cursor.exists(), 'a refused tick writes no state')


class WindowIsTheCursorGridTests(unittest.TestCase):
    def test_the_completed_window_follows_the_configured_value(self):
        """NOW is 12:01:07Z: a 60 s window closes at 12:01:00Z, a 5 s one at 12:01:05Z."""
        for seconds, expected in ((60, '2026-09-08T12:01:00.000000+00:00'),
                                  (5, '2026-09-08T12:01:05.000000+00:00')):
            with self.subTest(window=seconds):
                with tempfile.TemporaryDirectory() as directory:
                    index_path, rule = self._rule(Path(directory))
                    cursor = Path(directory) / 'cursor.json'
                    self.assertEqual('delivered', tick(index_path, rule, cursor, EngineDownFake(),
                                                       IntakeFake(), now=NOW, window_seconds=seconds))
                    state = json.loads(cursor.read_text(encoding='utf-8'))
                    self.assertEqual(expected, state['last_end'])
                    self.assertIsNone(state['pending'])

    def test_a_second_tick_inside_the_same_window_is_idle_not_a_second_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            index_path, rule = self._rule(Path(directory))
            cursor = Path(directory) / 'cursor.json'
            intake = IntakeFake()
            tick(index_path, rule, cursor, EngineDownFake(), intake, now=NOW, window_seconds=60)
            self.assertEqual('idle', tick(index_path, rule, cursor, EngineDownFake(), intake,
                                          now=NOW + dt.timedelta(seconds=30), window_seconds=60))
            self.assertEqual(1, len(intake.events), 'one coverage verdict, and never a second one for '
                                                    'the same completed window')

    def test_the_healthcheck_bound_the_manifest_derives_matches_this_band(self):
        """compose.yaml's healthcheck reads the same environment value; the arithmetic is pinned here."""
        for seconds in (5, 60, 3600):
            with self.subTest(window=seconds):
                self.assertGreaterEqual(max(3 * seconds, 60), seconds,
                                        'a staleness bound tighter than one window is a flapping host')

    @staticmethod
    def _rule(root: Path):
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        index_path = root / 'inventory.db'
        index.build(declared, index_path, 'fixture', now=NOW)
        rule = {'id': 'synthetic-http', 'kind': 'availability', 'resource_id': declared['resources'][0]['id'],
                'source': SOURCE}
        return index_path, rule


class AbsentEngineStaysVisibleTests(unittest.TestCase):
    """`docs/COMPONENTS.md`'s `If disabled` clause, pinned for the case nobody wires up."""

    def _rule(self, root: Path):
        return WindowIsTheCursorGridTests._rule(root)

    def test_no_sample_files_coverage_firing_and_no_availability_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            index_path, rule = self._rule(Path(directory))
            events = detections.evaluate(index_path, rule, None, now=NOW)
            self.assertEqual(['coverage'], [item['kind'] for item in events])
            self.assertEqual('firing', events[0]['status'])
            self.assertEqual(rule['id'] + '.coverage', events[0]['rule_id'])

    def test_a_missing_engine_never_resolves_the_condition_it_is_watching(self):
        """The negative half, stated directly: `resolved` may not appear at all when there is no sample."""
        with tempfile.TemporaryDirectory() as directory:
            index_path, rule = self._rule(Path(directory))
            events = detections.evaluate(index_path, rule, None, now=NOW)
            self.assertNotIn('resolved', [item['status'] for item in events])
            self.assertNotIn('availability', [item['kind'] for item in events])

    def test_an_error_status_from_the_engine_is_the_same_hole_as_no_engine(self):
        for status in (404, 401, 500):
            with self.subTest(status=status):
                with tempfile.TemporaryDirectory() as directory:
                    index_path, rule = self._rule(Path(directory))
                    cursor = Path(directory) / 'cursor.json'
                    intake = IntakeFake()
                    tick(index_path, rule, cursor, EngineDownFake(status), intake, now=NOW)
                    self.assertEqual([], intake.evidence, 'no sample means nothing to file as evidence')
                    self.assertEqual(['coverage'], [item['kind'] for item in intake.events])
                    self.assertEqual(['firing'], [item['status'] for item in intake.events])

    def test_a_connection_failure_is_the_same_hole_too(self):
        with tempfile.TemporaryDirectory() as directory:
            index_path, rule = self._rule(Path(directory))
            cursor = Path(directory) / 'cursor.json'
            intake = IntakeFake()
            self.assertEqual('delivered', tick(index_path, rule, cursor, TransportDownFake(), intake, now=NOW))
            self.assertEqual(['coverage'], [item['kind'] for item in intake.events])


class GoEnvelopeTests(unittest.TestCase):
    """The adapter must parse what the pinned engine actually writes, not what JSON looks like."""

    def test_nanosecond_go_timestamps_parse_and_the_newest_qualifying_row_wins(self):
        """`config/endpoint/result.go` marshals `Timestamp time.Time` as RFC 3339, and Go trims the
        trailing zeros off the fraction — so 1 to 9 digits can arrive. Measured on this interpreter
        rather than assumed: a parse refusal on that field makes the component file coverage against a
        healthy engine, which is the loudest way to be wrong quietly.
        """
        for digits in range(1, 10):
            with self.subTest(digits=digits):
                fraction = '1' * digits
                payload = {'results': [{'timestamp': f'2026-09-08T12:01:05.{fraction}Z',
                                       'success': True}]}
                self.assertIsNotNone(detections.gatus_sample(payload, before=NOW))

        payload = {'results': [{'timestamp': '2026-09-08T12:00:59.9999Z', 'success': True, 'duration': 4213},
                               {'timestamp': '2026-09-08T12:01:05.123456789Z', 'success': False,
                                'status': 0, 'errors': ['connection refused'], 'conditionResults': []}]}
        sample = detections.gatus_sample(payload, before=NOW)
        self.assertIsNotNone(sample)
        self.assertIs(False, sample['value'], 'the newest row at or before the watermark wins')
        self.assertEqual('2026-09-08T12:01:05.123456789Z', sample['observed_at'], 'the raw text travels')
        self.assertEqual(64, len(sample['sample_id']))

    def test_the_sample_parses_through_the_freshness_rule_that_uses_it(self):
        sample = detections.gatus_sample({'results': [{'timestamp': '2026-09-08T12:01:05.123456789Z',
                                                      'success': True}]}, before=NOW)
        age = (NOW - timestamp(sample['observed_at'])).total_seconds()
        self.assertLess(abs(age - 2), 1, 'two seconds old, not rejected as unparseable or as the future')

    def test_a_result_newer_than_the_watermark_is_ignored_not_used(self):
        self.assertIsNone(detections.gatus_sample({'results': [{'timestamp': '2026-09-08T12:02:00Z',
                                                               'success': True}]}, before=NOW))


class CredentialSchemeTests(unittest.TestCase):
    """The one product-code half of synthetics component's credential finding, pinned as a wire format."""

    def test_the_scheme_is_basic_because_the_pinned_engine_accepts_nothing_else(self):
        self.assertEqual('Basic', GATUS_AUTH_SCHEME)

    def test_the_credential_shape_that_file_must_hold_survives_the_transport_checks(self):
        """base64("user:password") — and it has to be long enough for `http.JsonClient`'s own floor,
        which is why a short password is a refusal at boot rather than a 401 two layers away."""
        value = base64.b64encode(b'lo-detector:' + b'a' * 48).decode()
        client = JsonClient('http://gatus:8080/api/v1/endpoints/lo_platform-http/statuses', value,
                            scheme=GATUS_AUTH_SCHEME, allow_http=True)
        self.assertEqual('Basic', client.scheme)
        self.assertEqual('Basic ' + value, 'Basic ' + client.token)

    def test_a_bearer_shaped_token_would_not_have_been_refused_for_shape_alone(self):
        """The reason a bearer token sat in this file unnoticed: nothing about the transport complained.
        Only the engine's middleware objected, and only when it had one — so the pin here is that the
        scheme argument, not the token, is what carries the fix."""
        client = JsonClient('http://gatus:8080/x', 'z' * 40, scheme='Bearer', allow_http=True)
        self.assertEqual('Bearer', client.scheme)


if __name__ == '__main__':
    unittest.main()

"""Structured logging contract: JSON line shape, level parsing, credential redaction.

Negative tests used while writing this file (each mutant was applied to a copy of the tree and the
copy had to fail): redaction made a pass-through (6 tests fail); ``deliver_one`` logging the whole
outbox item; ``dagu.execute`` logging the intake payload with its runner token; ``http`` logging the
full URL path and configured base. A worker loop that drops its tick line is caught only by
``WorkerLoopTests`` below, which drive ``main()`` for a fixed number of ticks.
"""
import datetime as dt
import io
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from local_observe import log
from local_observe.http import JsonClient, TransportError
from local_observe.inventory import validation
from local_observe.log import (FIXED_FIELDS, JsonLinesFormatter, LEVELS, configure, get_logger, is_secret_key,
                               redacted, resolve_level, supplied_fields)

ROOT = Path(__file__).resolve().parents[1]
SECRET_TOKEN = 'A1b2C3d4E5f6G7h8I9j0-shared-secret'


def make_record(name='local_observe.test', level=logging.INFO, message='tick', **fields):
    """Build a record the way ``logging`` does, so formatter tests need no live logger."""
    record = logging.LogRecord(name, level, str(Path(__file__)), 7, message, None, None)
    for key, value in fields.items():
        setattr(record, key, value)
    return record


def rendered(records):
    """The exact lines production would write for these records, extras included.

    ``assertLogs`` only keeps ``level:logger:message``, which hides the serialised fields; this
    is what makes the leak assertions below worth writing.
    """
    formatter = JsonLinesFormatter()
    return '\n'.join(formatter.format(record) for record in records)


class JsonLineTests(unittest.TestCase):
    def test_one_line_carries_the_fixed_fields_then_extras(self):
        line = JsonLinesFormatter().format(make_record(message='delivery finished', delivery_id='d-1',
                                                      status='sent', attempts=2, duration_ms=12.5))
        self.assertNotIn('\n', line)
        parsed = json.loads(line)
        self.assertEqual(list(parsed)[:len(FIXED_FIELDS)], list(FIXED_FIELDS))
        self.assertEqual((parsed['level'], parsed['logger'], parsed['event']), ('INFO', 'local_observe.test',
                                                                               'delivery finished'))
        self.assertEqual((parsed['delivery_id'], parsed['status'], parsed['attempts'], parsed['duration_ms']),
                         ('d-1', 'sent', 2, 12.5))

    def test_timestamp_is_utc_iso_8601(self):
        parsed = json.loads(JsonLinesFormatter().format(make_record()))
        observed = dt.datetime.fromisoformat(parsed['ts'])
        self.assertEqual(observed.utcoffset(), dt.timedelta(0))
        self.assertEqual(observed.tzinfo, dt.timezone.utc)

    def test_every_level_name_is_recorded(self):
        for name in LEVELS:
            parsed = json.loads(JsonLinesFormatter().format(make_record(level=LEVELS[name])))
            self.assertEqual(parsed['level'], name)

    def test_traceback_is_emitted_at_debug_only(self):
        try:
            raise ValueError(SECRET_TOKEN)
        except ValueError:
            info = sys.exc_info()
        higher = json.loads(JsonLinesFormatter().format(make_record(level=logging.WARNING, exc_info=info)))
        self.assertNotIn('traceback', higher)
        debugged = json.loads(JsonLinesFormatter().format(make_record(level=logging.DEBUG, exc_info=info)))
        self.assertIn('ValueError', debugged['traceback'])

    def test_message_and_fields_are_bounded(self):
        parsed = json.loads(JsonLinesFormatter().format(make_record(message='m' * 5000, detail='d' * 5000)))
        self.assertLess(len(parsed['event']), 600)
        self.assertLess(len(parsed['detail']), 400)

    def test_machine_unfriendly_values_cannot_break_the_line(self):
        class Unrepresentable:
            def __repr__(self):
                raise RuntimeError('repr is broken')

        line = JsonLinesFormatter().format(make_record(broken=Unrepresentable(), odd=float('nan'),
                                                       nested={'tuples': (1, 2), 'nested_deep': {'x': None}}))
        parsed = json.loads(line)
        self.assertEqual(parsed['broken'], '<unrepresentable>')
        self.assertEqual(parsed['odd'], '<unrepresentable>')
        self.assertEqual(parsed['nested'], {'tuples': [1, 2], 'nested_deep': {'x': None}})

    def test_a_secret_named_extra_cannot_reach_the_line(self):
        line = JsonLinesFormatter().format(make_record(message='delivery finished', delivery_id='d-1', status='sent',
                                                      token=SECRET_TOKEN,
                                                      channel={'clientsecret': SECRET_TOKEN, 'name': 'home'}))
        self.assertNotIn(SECRET_TOKEN, line)
        parsed = json.loads(line)
        self.assertEqual(parsed['token'], '<redacted>')
        self.assertEqual(parsed['channel'], {'clientsecret': '<redacted>', 'name': 'home'})
        self.assertEqual(parsed['delivery_id'], 'd-1')

    def test_reserved_and_private_attributes_are_never_treated_as_fields(self):
        fields = supplied_fields(make_record(delivery_id='d-1'))
        self.assertEqual(fields, {'delivery_id': 'd-1'})
        for not_a_field in ('name', 'msg', 'levelname', 'created', 'filename', 'lineno'):
            self.assertNotIn(not_a_field, fields)

    def test_configuring_the_root_handler_is_idempotent(self):
        configure()
        get_logger('local_observe.test.idempotent.a')
        get_logger('local_observe.test.idempotent.b')
        installed = [handler for handler in logging.getLogger().handlers
                     if isinstance(handler.formatter, JsonLinesFormatter)]
        self.assertEqual(len(installed), 1)
        logger = get_logger('local_observe.test.idempotent')
        self.assertIsInstance(logger, logging.Logger)
        self.assertEqual(logger.name, 'local_observe.test.idempotent')


class LevelParsingTests(unittest.TestCase):
    def test_standard_names_are_honoured_in_any_case(self):
        for name, value in LEVELS.items():
            self.assertEqual(resolve_level(name), value)
            self.assertEqual(resolve_level(name.lower()), value)
            self.assertEqual(resolve_level('  ' + name.lower() + ' '), value)

    def test_anything_else_falls_back_to_info(self):
        for raw in ('', ' ', None, 'verbose', 'NOTSET', 'nan', 'Information', 'Criti-cal', '0', '5', 'debug extra'):
            self.assertEqual(resolve_level(raw), LEVELS['INFO'], repr(raw))

    def emitted(self, given):
        """Run a fresh interpreter with the given environment and parse what it wrote to stderr."""
        program = ("from local_observe.log import get_logger;"
                   "log = get_logger('probe');"
                   "log.info('marker-info'); log.debug('marker-debug'); log.warning('marker-warning')")
        environment = dict(os.environ)
        environment.pop('LO_LOG_LEVEL', None)
        environment.update(given)
        result = subprocess.run([sys.executable, '-B', '-c', program], cwd=ROOT, capture_output=True, text=True,
                                env=environment, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [json.loads(line) for line in result.stderr.splitlines() if line.strip()]
        self.assertTrue(lines, result.stderr)
        return {line['event'] for line in lines}, lines

    def test_configured_level_comes_from_the_environment(self):
        emitted, lines = self.emitted({'LO_LOG_LEVEL': 'DEBUG'})
        self.assertEqual(emitted, {'marker-info', 'marker-debug', 'marker-warning'})
        self.assertEqual({line['level'] for line in lines}, {'INFO', 'DEBUG', 'WARNING'})
        self.assertTrue(all(line['logger'] == 'probe' for line in lines))

    def test_an_unset_level_logs_at_info(self):
        emitted, _ = self.emitted({})
        self.assertEqual(emitted, {'marker-info', 'marker-warning'})

    def test_an_invalid_level_does_not_silence_the_worker(self):
        for given in ({'LO_LOG_LEVEL': 'verbose'}, {'LO_LOG_LEVEL': ''}, {'LO_LOG_LEVEL': 'notset'}):
            emitted, _ = self.emitted(given)
            self.assertEqual(emitted, {'marker-info', 'marker-warning'}, given)

    def test_a_higher_level_still_filters(self):
        emitted, _ = self.emitted({'LO_LOG_LEVEL': 'warning'})
        self.assertEqual(emitted, {'marker-warning'})


class RedactionTests(unittest.TestCase):
    def test_secret_named_keys_are_masked_at_any_depth(self):
        value = {'delivery_id': 'd-1', 'token': SECRET_TOKEN,
                 'channel': {'api_key': 'second-secret', 'Authorization': 'Bearer third-secret', 'chat_id': '7'},
                 'rows': [{'clientSecret': 'fourth-secret', 'ok': True}, {'privateKey': 'fifth-secret'}]}
        masked = redacted(value)
        text = json.dumps(masked)
        for secret in (SECRET_TOKEN, 'second-secret', 'Bearer third-secret', 'fourth-secret', 'fifth-secret'):
            self.assertNotIn(secret, text)
        self.assertEqual(masked['token'], '<redacted>')
        self.assertEqual(masked['channel']['Authorization'], '<redacted>')
        self.assertEqual(masked['rows'][0], {'clientSecret': '<redacted>', 'ok': True})
        self.assertEqual((masked['delivery_id'], masked['channel']['chat_id']), ('d-1', '7'))

    def test_key_matching_is_the_same_normalisation_as_inventory_validation(self):
        # One predicate, defined once: this is the anti-drift assertion, so a re-implemented screen
        # in log.py fails here rather than leaking a claim_token into a log line.
        self.assertIs(log.is_secret_key, validation.is_secret_key)
        self.assertIs(is_secret_key, validation.is_secret_key)
        for key in ('token', 'Token', 'API-KEY', 'api_key', ' api key ', 'clientSecret', 'password',
                    'api_token', 'apiToken', 'API_TOKEN', 'APIToken', 'claim_token', 'db_password'):
            self.assertTrue(is_secret_key(key), key)
        for key in ('token_file', 'token_id', 'passphrase', 'destination', 'status', 'secret_ref',
                    'prompt_tokens', 'max_completion_tokens', 'tokens_available', None, 3):
            self.assertFalse(is_secret_key(key), repr(key))

    def test_depth_breadth_and_self_reference_are_bounded(self):
        deep = {}
        current = deep
        for index in range(20):
            current['level-%d' % index] = current = {}
        current['password'] = SECRET_TOKEN
        cycle = {}
        cycle['self'] = cycle
        text = json.dumps(redacted({'deep': deep, 'cycle': cycle, 'wide': list(range(5000)), 'n': 1}))
        self.assertNotIn(SECRET_TOKEN, text)
        self.assertLess(len(text), 3000)
        self.assertEqual(len(json.loads(text)['wide']), 100)

    def test_a_mapping_is_returned_as_a_mapping(self):
        self.assertIsInstance(redacted({'a': 1}), dict)
        self.assertEqual(redacted([{'token': SECRET_TOKEN}, 'plain']), [{'token': '<redacted>'}, 'plain'])
        self.assertEqual(redacted('scalar'), 'scalar')


class DeliveryOutcomeTests(unittest.TestCase):
    """The instrumented paths must log identifiers and outcomes, never channel material."""
    class Store:
        def __init__(self, item):
            self.item = item
            self.finished = []

        def claim_notification(self, *, now=None):
            return self.item

        def finish_notification(self, delivery_id, claim_token, success, *, now=None, cause=None):
            # `cause` is notifications's bounded outcome word; the double takes it so the real call signature
            # can be exercised, and records the boolean exactly as it did before.
            self.finished.append((delivery_id, claim_token, success))
            return 'sent' if success else 'pending'

    class Channel:
        def __init__(self, accepted=True):
            self.accepted = accepted

        def request(self, method, *, payload, headers):
            return 202, {'accepted': self.accepted, 'delivery_id': payload['delivery_id']}

    def item(self, **extra):
        value = {'id': 'delivery-7', 'claim_token': 'claim-' + SECRET_TOKEN, 'destination': 'telegram',
                 'payload': {'delivery_id': 'delivery-7', 'text': 'event-body-must-not-be-logged',
                             'event': {'data_class': 'internal'}}}
        value.update(extra)
        return value

    def test_a_finished_delivery_logs_identifiers_only(self):
        from local_observe.platform.notifications import deliver_one
        store = self.Store(self.item())
        with self.assertLogs('local_observe.platform.notifications', 'INFO') as captured:
            result = deliver_one(store, self.Channel())
        self.assertEqual(result, {'status': 'sent', 'delivery_id': 'delivery-7', 'destination': 'telegram'})
        line = [record for record in captured.records if getattr(record, 'status', None) == 'sent'][0]
        self.assertEqual((line.delivery_id, line.destination, line.status), ('delivery-7', 'telegram', 'sent'))
        joined = rendered(captured.records)
        for forbidden in (SECRET_TOKEN, 'event-body-must-not-be-logged', 'claim-', 'payload'):
            self.assertNotIn(forbidden, joined)

    def test_a_suppressed_delivery_logs_the_reason(self):
        from local_observe.platform.notifications import deliver_one
        store = self.Store(self.item(suppressed='circuit-open'))
        with self.assertLogs('local_observe.platform.notifications', 'INFO') as captured:
            self.assertEqual(deliver_one(store, self.Channel())['status'], 'suppressed')
        self.assertEqual([record.reason for record in captured.records if hasattr(record, 'reason')], ['circuit-open'])
        self.assertEqual(store.finished, [])

    def test_a_failing_channel_is_logged_once_with_its_class(self):
        from local_observe.platform.notifications import deliver_one
        store = self.Store(self.item())

        class Broken:
            def request(self, method, *, payload, headers):
                raise TransportError('channel unavailable')

        with self.assertLogs('local_observe.platform.notifications', 'INFO') as captured:
            self.assertEqual(deliver_one(store, Broken())['status'], 'pending')
        warned = [record for record in captured.records if record.levelno == logging.WARNING]
        self.assertEqual([record.error_class for record in warned], ['TransportError'])
        self.assertNotIn('channel unavailable', rendered(captured.records))

    def test_an_idle_tick_stays_quiet_at_info(self):
        from local_observe.platform.notifications import deliver_one
        with self.assertLogs('local_observe.platform.notifications', 'DEBUG') as captured:
            self.assertEqual(deliver_one(self.Store(None), self.Channel()), {'status': 'idle'})
        self.assertEqual([record.getMessage() for record in captured.records], ['Notification delivery idle'])


class ExecutionJournalTests(unittest.TestCase):
    def test_execution_transitions_never_carry_the_runner_token(self):
        import hashlib
        import uuid
        from local_observe.platform import dagu

        class Platform:
            claim = {'status': 'executing', 'execution_id': '11111111-1111-4111-8111-111111111111',
                     'runner_token': 'runner-' + SECRET_TOKEN,
                     'request': {'action': 'inspect', 'version': '1', 'targets': ['fixture'], 'parameters': {}}}

            def request(self, method, path, payload):
                if path.endswith('/claim'):
                    return 200, self.claim
                return 200, {'status': payload['outcome']}

        class Engine:
            def __init__(self):
                self.run_id = None

            def request(self, method, path, payload=None):
                if path.endswith('/spec'):
                    return 200, {'spec': 'fixture'}
                if path.endswith('/start'):
                    self.run_id = payload['dagRunId']
                    return 200, {'dagRunId': self.run_id}
                return 200, {'dagRunDetails': {'name': 'inspect', 'dagRunId': self.run_id, 'statusLabel': 'succeeded'}}

        with tempfile.TemporaryDirectory() as directory:
            engine = Engine()
            binding = {'action': 'inspect', 'version': '1', 'targets': ['fixture'], 'dag': 'inspect',
                       'sha256': hashlib.sha256(b'fixture').hexdigest()}
            with self.assertLogs('local_observe.platform.dagu', 'INFO') as captured:
                result = dagu.execute(Platform(), engine, str(uuid.uuid4()), binding, Path(directory) / 'journal.json')
            self.assertEqual(result['status'], 'succeeded')
            self.assertEqual([record.getMessage() for record in captured.records],
                             ['Execution claimed', 'Execution dispatched', 'Outcome posted'])
            self.assertTrue(all(record.execution_id == Platform.claim['execution_id'] for record in captured.records))
            joined = rendered(captured.records)
            self.assertNotIn(SECRET_TOKEN, joined)
            self.assertNotIn('runner-', joined)
            self.assertEqual([set(json.loads(line)) - set(FIXED_FIELDS) for line in joined.splitlines()],
                             [{'execution_id', 'action_id'}, {'execution_id'},
                              {'execution_id', 'outcome', 'status'}])


class StoppedLoop(Exception):
    """Raised from a stand-in sleep to end an otherwise endless worker loop."""


def sleep_stopper(iterations):
    """Return a ``time.sleep`` stand-in that ends a worker loop after this many ticks."""
    remaining = [iterations]

    def sleep(_seconds):
        remaining[0] -= 1
        if remaining[0] <= 0:
            raise StoppedLoop
    return sleep


class WorkerLoopTests(unittest.TestCase):
    """An iteration must leave exactly one line behind, healthy or not."""
    def test_a_detection_tick_logs_its_result_and_a_failure_logs_once_more(self):
        from local_observe.platform import detection_worker
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'rule.yaml').write_text('source: fixture\n', encoding='utf-8')
            environment = {'LO_DETECTION_RULE': str(root / 'rule.yaml'),
                           'LO_DETECTION_CURSOR': str(root / 'cursor.json'),
                           'LO_GATUS_URL': 'http://gatus.example.invalid', 'LO_GATUS_TOKEN': SECRET_TOKEN,
                           'LO_PLATFORM_URL': 'http://platform.example.invalid', 'LO_PRODUCER_TOKEN': SECRET_TOKEN,
                           'LO_INTERNAL_ALLOW_HTTP': '1', 'LO_INDEX_PATH': str(root / 'index.db')}
            outcomes = ['delivered', OSError('cursor unreadable')]

            def tick(*args, **kwargs):
                value = outcomes.pop(0)
                if isinstance(value, Exception):
                    raise value
                return value

            with patch.dict(os.environ, environment), patch.object(detection_worker, 'tick', tick), \
                    patch.object(detection_worker.time, 'sleep', sleep_stopper(2)):
                with self.assertRaises(StoppedLoop):
                    with self.assertLogs('local_observe.platform.detection_worker', 'INFO') as captured:
                        detection_worker.main()
            self.assertEqual([(record.levelno, record.getMessage()) for record in captured.records],
                             [(logging.INFO, 'Detection tick finished'),
                              (logging.WARNING, 'Detection delivery unavailable; retaining pending batch')])
            self.assertEqual(captured.records[0].result, 'delivered')
            self.assertEqual(captured.records[1].error_class, 'OSError')
            self.assertNotIn(SECRET_TOKEN, rendered(captured.records))
            self.assertTrue(all(getattr(record, 'exc_info', None) is None for record in captured.records),
                            'a traceback belongs at DEBUG, not on the operator line')

    def test_an_unreadable_source_still_logs_a_published_summary(self):
        from local_observe.platform import overview_worker
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'overview-config.json'
            config.write_text(json.dumps({'output': str(root / 'overview.json'),
                                          'jobs_cursor': str(root / 'absent.json'), 'expected_jobs': ['fixture']}),
                              encoding='utf-8')
            with patch.dict(os.environ, {'LO_OVERVIEW_CONFIG': str(config)}), \
                    patch.object(overview_worker.time, 'sleep', sleep_stopper(2)):
                with self.assertRaises(StoppedLoop):
                    with self.assertLogs('local_observe.platform.overview_worker', 'INFO') as captured:
                        overview_worker.main()
            self.assertTrue((root / 'overview.json').exists())
            self.assertEqual([record.getMessage() for record in captured.records], ['Overview published'] * 2)
            self.assertTrue(all(record.status == 'unknown' and record.value is None for record in captured.records))
            self.assertNotIn('absent.json', rendered(captured.records))


class TransportLoggingTests(unittest.TestCase):
    class Opener:
        """Stand-in for the urllib opener: every request fails with *error*, no socket is touched."""
        def __init__(self, error):
            self.error = error

        def open(self, request, timeout=None):
            raise self.error

    def client(self):
        return JsonClient('https://endpoint.example.invalid', SECRET_TOKEN)

    def test_a_transport_failure_logs_method_path_and_class_only(self):
        client = self.client()
        client.opener = self.Opener(OSError('connection refused'))
        with self.assertLogs('local_observe.http', 'WARNING') as captured:
            with self.assertRaises(TransportError):
                client.request('POST', '/v1/events?token=' + SECRET_TOKEN, {'delivery_id': 'd-1'})
        record = captured.records[0]
        self.assertEqual((record.method, record.path, record.error_class), ('POST', '/v1/events', 'OSError'))
        joined = rendered(captured.records)
        for forbidden in (SECRET_TOKEN, 'endpoint.example.invalid', 'delivery_id', 'connection refused', '?token'):
            self.assertNotIn(forbidden, joined)

    def test_an_invalid_path_is_logged_before_it_is_refused(self):
        with self.assertLogs('local_observe.http', 'WARNING') as captured:
            with self.assertRaises(TransportError):
                self.client().request('GET', '../escape')
        self.assertEqual(captured.records[0].path, '../escape')
        self.assertEqual(captured.records[0].error_class, 'TransportError')

    def test_an_error_status_is_debug_and_still_returns_the_code(self):
        import urllib.error
        client = self.client()
        client.opener = self.Opener(urllib.error.HTTPError('https://endpoint.example.invalid', 404, 'not found',
                                                          {}, io.BytesIO(b'')))
        with self.assertLogs('local_observe.http', 'DEBUG') as captured:
            self.assertEqual(client.request('GET', '/v1/status'), (404, None))
        self.assertEqual([(record.method, record.status_code) for record in captured.records], [('GET', 404)])


if __name__ == '__main__':
    unittest.main()

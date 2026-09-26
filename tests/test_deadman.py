"""The independent platform-availability witness: its state machine, and the job observe standard check-in target.

Two halves are pinned here. The first is the pre-job observe standard contract, which job observation did not change: an outage
grace, a persisted failure clock, a durable outbox that retries the exact item, recovery under a
stable incident identity, and no dependency on platform storage or intake. The second is what job observe standard
moved: the reporting target is a Healthchecks check-in (`components/control/job-observe/CONTRACT.md`)
read from a mounted file, a missed check-in is an event of `kind='availability'` carrying the job's
declared resource, and a check-in that a monitor refuses is not an acknowledgement.
"""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
import uuid

from local_observe.http import TransportError
from local_observe.platform import deadman
from local_observe.platform.state import StateError, validate_event

NOW = dt.datetime(2026, 9, 6, 15, tzinfo=dt.timezone.utc)
# A synthetic check code in the shape Healthchecks mints (a UUID, appended to PING_ENDPOINT).
PING = 'https://checks.example.org/ping/11111111-1111-1111-1111-111111111111'


class Channel:
    def __init__(self):
        self.payloads = []
        self.failed = False

    def request(self, method, payload, headers):
        self.payloads.append(payload)
        if self.failed:
            raise TransportError('offline')
        return 200, {'accepted': True, 'delivery_id': payload['delivery_id']}


class DeadmanTests(unittest.TestCase):
    def test_external_failure_recovery_and_durable_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'witness.json'
            channel = Channel()
            deadman.tick(path, False, channel, now=NOW, grace_seconds=2)
            channel.failed = True
            with self.assertRaises(TransportError):
                deadman.tick(path, False, channel, now=NOW + dt.timedelta(seconds=2), grace_seconds=2)
            first = json.loads(path.read_text())['pending'][0]
            channel.failed = False
            deadman.tick(path, True, channel, now=NOW + dt.timedelta(seconds=3), grace_seconds=2)
            deadman.tick(path, True, channel, now=NOW + dt.timedelta(seconds=4), grace_seconds=2)
            self.assertEqual(channel.payloads[1], first)
            self.assertEqual(channel.payloads[-1]['transition'], 'resolved')
            self.assertEqual(channel.payloads[-1]['incident_id'], first['incident_id'])
            self.assertEqual(json.loads(path.read_text())['pending'], [])

    def test_the_missed_checkin_event_is_a_canonical_availability_event(self):
        """kind='availability' with the job's declared resource, accepted by the state layer unchanged.

        The witness must not import platform storage, so it builds the event itself; this is the test
        that keeps the private builder from drifting away from the shape intake actually admits.
        `state.py` admits availability/coverage/threshold/drift and has no 'job' kind.
        """
        resource = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'witness.json'
            channel = Channel()
            deadman.tick(path, False, channel, now=NOW + dt.timedelta(seconds=100), grace_seconds=2)
            self.assertEqual(channel.payloads, [], 'inside the grace window nothing is reported')
            deadman.tick(path, False, channel, now=NOW + dt.timedelta(seconds=102), grace_seconds=2,
                         resource_id=resource)
            event = channel.payloads[0]['event']
            self.assertEqual(event['kind'], 'availability')
            self.assertEqual(event['resource_id'], resource)
            self.assertEqual(event['rule_id'], deadman.CHECKIN_RULE)
            self.assertEqual(event['status'], 'firing')
            validate_event(event, NOW + dt.timedelta(minutes=5))     # raises StateError if the shape lies
            self.assertEqual(event, deadman.checkin_event(resource_id=resource, firing=True,
                                                          now=dt.datetime.fromisoformat(event['observed_at'])))

    def test_an_unnamed_witness_still_reports_without_a_resource(self):
        """The pre-job observe standard payload shape, kept: no declared job means resource_id stays null."""
        with tempfile.TemporaryDirectory() as directory:
            channel = Channel()
            deadman.tick(Path(directory) / 'witness.json', False, channel, now=NOW + dt.timedelta(seconds=100),
                         grace_seconds=2)
            deadman.tick(Path(directory) / 'witness.json', False, channel, now=NOW + dt.timedelta(seconds=102),
                         grace_seconds=2)
            self.assertIsNone(channel.payloads[0]['event']['resource_id'])
            validate_event(channel.payloads[0]['event'], NOW + dt.timedelta(minutes=5))


class FakeResponse:
    def __init__(self, status):
        self.status = status
        self.body = b'OK'

    def read(self, limit):
        return self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeOpener:
    """Records the URL each check-in actually requested; the ping URL must never be guessed twice."""

    def __init__(self, status=200, error=None):
        self.urls = []
        self.status = status
        self.error = error

    def open(self, request, timeout=None):
        self.urls.append(request.full_url)
        if not 1 <= timeout <= 20:
            raise AssertionError('check-in timeout must stay bounded')
        if self.error:
            raise self.error
        return FakeResponse(self.status)


class HealthchecksPingTests(unittest.TestCase):
    def test_targets_are_bounded_endpoints(self):
        for bad in ('http://checks.example.org/ping/11111111-1111-1111-1111-111111111111',
                    'https://user@checks.example.org/ping/abc', 'https://checks.example.org/ping/abc?msg=x',
                    'https://checks.example.org/ping/abc#frag', 'https://checks.example.org',
                    'https://checks.example.org/ping/../../etc', '  https://checks.example.org/ping/abc',
                    'ftp://checks.example.org/ping/abc', ''):
            with self.subTest(target=bad), self.assertRaises(ValueError):
                deadman.HealthchecksPing(bad)
        # Plaintext is reachable only by the same opt-in every other internal client uses.
        self.assertIsNotNone(deadman.HealthchecksPing(
            'http://127.0.0.1:18097/ping/11111111-1111-1111-1111-111111111111', allow_http=True))
        for timeout in (0, 21, 3600):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                deadman.HealthchecksPing(PING, timeout=timeout)

    def test_success_and_failure_pings_differ_only_by_the_documented_suffix(self):
        opener = FakeOpener()
        client = deadman.HealthchecksPing(PING, opener=opener)
        self.assertEqual(client.check_in(True), 200)
        self.assertEqual(client.check_in(False), 200)
        self.assertEqual(opener.urls, [PING, PING + '/fail'])

    def test_a_refused_checkin_is_not_an_acknowledgement(self):
        """404 means Healthchecks does not know that code (a rebuilt check, a restored database)."""
        payload = self.transition('opened')
        client = deadman.HealthchecksPing(PING, opener=FakeOpener(status=404))
        self.assertEqual(client.check_in(True), 404)
        code, receipt = client.request('POST', payload=payload,
                                       headers={'Idempotency-Key': payload['delivery_id']})
        self.assertEqual((code, receipt['accepted']), (404, False))

    def test_an_unreachable_monitor_raises_so_the_loop_can_log_and_continue(self):
        client = deadman.HealthchecksPing(PING, opener=FakeOpener(error=urllib.error.URLError('refused')))
        with self.assertRaises(TransportError):
            client.check_in(True)

    def transition(self, kind):
        delivery_id = str(uuid.uuid4())
        return {'delivery_id': delivery_id, 'incident_id': str(uuid.uuid4()), 'transition': kind,
                'event': deadman.checkin_event(resource_id=None, firing=kind == 'opened', now=NOW)}

    def test_the_channel_contract_is_refused_before_any_request_leaves(self):
        opener = FakeOpener()
        client = deadman.HealthchecksPing(PING, opener=opener)
        good = self.transition('opened')
        for call in (('GET', '', good), ('POST', '/extra', good), ('POST', '', None),
                     ('POST', '', dict(good, transition='maybe')),
                     ('POST', '', dict(good, event={'data_class': 'restricted'}))):
            with self.subTest(call=call[0] + ' ' + str(bool(call[2]))), self.assertRaises(ValueError):
                client.request(*call[:2], payload=call[2], headers={'Idempotency-Key': good['delivery_id']})
        # Identity first, network second: a mismatched key must not spend the check-in.
        with self.assertRaises(ValueError):
            client.request('POST', payload=good, headers={'Idempotency-Key': str(uuid.uuid4())})
        with self.assertRaises(ValueError):
            client.request('POST', payload=good, headers=None)
        self.assertEqual(opener.urls, [])

    def test_transitions_land_on_the_right_side_of_the_check(self):
        opener = FakeOpener()
        client = deadman.HealthchecksPing(PING, opener=opener)
        opened, resolved = self.transition('opened'), self.transition('resolved')
        client.request('POST', payload=opened, headers={'Idempotency-Key': opened['delivery_id']})
        client.request('POST', payload=resolved, headers={'Idempotency-Key': resolved['delivery_id']})
        self.assertEqual(opener.urls, [PING + '/fail', PING])

    def test_a_refused_checkin_keeps_the_exact_item_pending_in_the_witness_state(self):
        """The durable outbox rule, re-proved against the new target instead of a chat channel.

        Timeline: fail (grace not elapsed) -> fail (opens, one pending item, monitor refuses) -> fail
        again (no second copy queued) -> recover (queues the resolved item and delivers the head) ->
        recover again (drains). Every step asserts the stored file, not a return value.
        """
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'witness.json'
            refusing = deadman.HealthchecksPing(PING, opener=FakeOpener(status=404))
            deadman.tick(path, False, refusing, now=NOW + dt.timedelta(seconds=100), grace_seconds=2)
            self.assertEqual(json.loads(path.read_text())['pending'], [], 'inside the grace, nothing is reported')
            deadman.tick(path, False, refusing, now=NOW + dt.timedelta(seconds=102), grace_seconds=2)
            self.assertEqual(len(json.loads(path.read_text())['pending']), 1)
            deadman.tick(path, False, refusing, now=NOW + dt.timedelta(seconds=103), grace_seconds=2)
            self.assertEqual(len(json.loads(path.read_text())['pending']), 1,
                             'a refused delivery must not queue a second copy')
            accepting = deadman.HealthchecksPing(PING, opener=FakeOpener())
            deadman.tick(path, True, accepting, now=NOW + dt.timedelta(seconds=104), grace_seconds=2)
            deadman.tick(path, True, accepting, now=NOW + dt.timedelta(seconds=105), grace_seconds=2)
            state = json.loads(path.read_text())
            self.assertEqual(state['pending'], [])
            self.assertIsNone(state['incident_id'])
            self.assertEqual(FakeOpener().urls, [], 'the transitions went through the injected openers')

    def test_a_malformed_or_missing_checkin_target_refuses_the_process_at_boot(self):
        """A witness with no deadline owner is the gap job observation closed; it must not start unwatched."""
        for value in ('not-a-url', 'https://checks.example.org', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                deadman.HealthchecksPing(value)


class CredentialShapeTests(unittest.TestCase):
    def test_the_ping_url_is_read_as_a_mounted_file_credential(self):
        """LO_HEALTHCHECKS_PING_FILE, not an environment value: the URL alone marks a job up."""
        with tempfile.TemporaryDirectory() as directory:
            held = Path(directory) / 'healthchecks-ping'
            held.write_text(PING, encoding='utf-8')
            from local_observe.credentials import read_credential
            self.assertEqual(read_credential('LO_HEALTHCHECKS_PING',
                                             environ={'LO_HEALTHCHECKS_PING_FILE': str(held)}), PING)
            # The env fallback still works (one operator, one container, by hand) but the file wins.
            self.assertEqual(read_credential('LO_HEALTHCHECKS_PING', environ={
                'LO_HEALTHCHECKS_PING_FILE': str(held), 'LO_HEALTHCHECKS_PING': 'https://elsewhere.example/ping/x'}),
                PING)

    def test_the_witness_imports_stay_free_of_the_storage_layer(self):
        """The witness's independence claim, as a test: deadman must not reach platform state.

        It holds a reader credential and a ping URL. Importing the store (or a producer client) into
        this process would let the monitored system silence the thing monitoring it -- see ARCHITECTURE
        3.5, "keep the independent dead-man outside the scheduler failure boundary".
        """
        source = Path(deadman.__file__).read_text(encoding='utf-8')
        for forbidden in ('from .state import', 'import sqlite3', 'Store(', '/v1/events'):
            with self.subTest(text=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()

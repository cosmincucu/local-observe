"""Conformance client for an isolated platform network.

Package ``_lib`` beside this script in the ``/checks`` mount. Credentials remain in
memory. The Gatus probe reads its HTTP Basic pair from the mounted file and its
endpoint from ``/checks/gatus-endpoint.json``. Missing or invalid configuration is
refused; the endpoint is constrained to the expected engine and status route.
"""
import argparse
import base64
import binascii
from contextlib import closing
import sqlite3
import datetime as dt
import json
import os
from pathlib import Path
import time
import sys
import urllib.parse

sys.path.insert(0, '/app')
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _lib.require import refuse_optimized, require
from local_observe.credentials import read_credential
from local_observe.http import JsonClient
from local_observe.inventory.validation import digest, read_document, utc_text
from local_observe.platform.detections import evaluate, gatus_sample
# Imported, never restated: the adapter that runs in the detector and this probe must not be able to
# disagree about the scheme they present to the same engine.
from local_observe.platform.detection_worker import GATUS_AUTH_SCHEME
from local_observe.platform.state import Store

#: Where ``scripts/conformance_platform_stage.py`` puts the same Basic credential the detector
#: presents: the platform container's read-only ``/config`` bind, at the fixed path the driver and
#: this file agree on. The platform manifest declares no variable for it - it declares none
#: conditionally, and a stage does not widen a shipped manifest to add one - which is exactly the
#: situation ``/config/notify-token`` is in, and the reason the path is a convention rather than an
#: environment read.
GATUS_CREDENTIAL_MOUNT = '/config/gatus-basic'
#: The endpoint the stage's detector was configured with, as one JSON line. Reading it is what keeps
#: this request and the detector's ``LO_GATUS_URL`` pointed at one key; the stage derives it from the
#: Gatus document, whose key is ``staging_synthetic-http`` (group + name, sanitised, upstream
#: ``config/key/key.go``), not the product config's ``lo_platform-http``.
GATUS_ENDPOINT_MOUNT = '/checks/gatus-endpoint.json'
GATUS_READ_TIMEOUT_SECONDS = 10
#: The one synthetic principal this stage mints, the one origin it is presented to and the one status
#: route it is read on. The stage driver derives the same three values
#: (``scripts/conformance_platform_stage.py``: ``GATUS_STAGE_USER``, ``GATUS_BASE_URL`` and
#: ``STAGE_ENDPOINT_KEY``), ``tests/test_platform_stage_wiring.py`` pins the two ends against each
#: other, and the endpoint document below is compared against all three: a probe that accepted any
#: ``http`` netloc would hand this credential to whatever a mounted file happened to name.
GATUS_STAGE_PRINCIPAL = 'lo-stage-detector'
GATUS_STATUS_ORIGIN = 'gatus:8080'
GATUS_STATUS_KEY = 'staging_synthetic-http'
GATUS_STATUS_PATH = '/api/v1/endpoints/' + GATUS_STATUS_KEY + '/statuses'
#: Bound on the endpoint document: the file this stage writes carries one url key and is under 100
#: bytes, so a larger one is not that file. Same order as ``read_credential``'s 4 KiB credential bound,
#: and the same reason - read a bounded amount, then parse, never the other way round.
GATUS_ENDPOINT_MAX_BYTES = 4096
#: One fixed sentence for a credential that is not a Basic pair. It names the variable and the rule,
#: never the bytes: a bearer-shaped file, an unpadded or re-encoded value and a pair naming another
#: principal all mean the same thing to the operator - this file is not what the stage wrote.
BASIC_TOKEN_REFUSAL = ('The Gatus credential named by LO_GATUS_TOKEN_FILE is not canonical padded '
                       'standard-base64 of a `user:password` pair. The pinned engine accepts HTTP Basic '
                       'and nothing else on this route, so a bearer-shaped token is refused here, before '
                       'any request is sent, rather than answered with a 401 in a container log')


def basic_pair(token):
    """Return ``(user, password)`` from a mounted Basic credential, or refuse without repeating it.

    :func:`local_observe.credentials.read_credential` already bounds the file, strips one newline and
    refuses control characters - which is a *line* check, and a bearer token is one line too. The
    requirement this satisfies is the one the engine's own middleware applies (fiber decodes this value
    with ``base64.StdEncoding``, strict about padding and about its alphabet): the bytes must decode,
    must re-encode to exactly the bytes that were read (so a value that merely happens to decode -
    unpadded, holding whitespace, or in the URL-safe alphabet - is refused rather than presented and
    401'd), must be printable ASCII, and must split into the principal this stage minted and a
    non-empty one-line password.

    Raises:
        ValueError: Any half of that fails. The message is :data:`BASIC_TOKEN_REFUSAL` or a sentence
            naming the expected principal: no password, and no bytes from the file, appears in it.
    """
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(BASIC_TOKEN_REFUSAL) from None
    require(base64.b64encode(raw).decode('ascii') == token, BASIC_TOKEN_REFUSAL)
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError(BASIC_TOKEN_REFUSAL) from None
    require(bool(text) and all(0x20 <= ord(character) < 0x7f for character in text), BASIC_TOKEN_REFUSAL)
    user, separator, password = text.partition(':')
    require(bool(separator) and bool(password), BASIC_TOKEN_REFUSAL)
    require(user == GATUS_STAGE_PRINCIPAL,
            'The mounted Gatus credential names a principal other than ' + GATUS_STAGE_PRINCIPAL
            + '; the stage renders its Gatus config for that one name, so a file holding another is not '
              'this stage\'s credential and is refused before it is presented to anything')
    return user, password


def gatus_client(credential_mount=GATUS_CREDENTIAL_MOUNT, endpoint_file=GATUS_ENDPOINT_MOUNT):
    """Return ``(client, path)`` for the one Gatus status endpoint this stage configured.

    Both arguments are paths inside this container, and both are read the same way every other
    credential here is read: :func:`local_observe.credentials.read_credential` takes the file, strips
    one trailing newline, bounds its size and refuses control characters, and its diagnostics name the
    variable and never the bytes. That generic check is not enough for a Basic pair, so :func:`basic_pair`
    then proves the file holds canonical padded standard-base64 of ``<the stage principal>:<one-line
    password>`` - the requirement this engine's middleware applies, and the one a bearer token fails -
    and the endpoint document is bounded, parsed and compared against the single route the stage derived
    before a client exists. Nothing here can send this credential to a host the stage did not name.

    Raises:
        ValueError: No credential is mounted, no endpoint file was written, the credential is not a
            Basic pair for this stage's principal, or the endpoint document is oversized, unreadable,
            not an object with one ``url``, or names any route other than this stage's own status
            endpoint on the engine service. Never a fallback to an unauthenticated or bearer request.
    """
    require(Path(credential_mount).is_file(),
            'No Gatus credential is mounted at ' + credential_mount + '; this stage authenticates, so the '
            'probe refuses rather than sending a request the closed engine would answer with 401 (or, worse, '
            'one an open engine would answer freely)')
    token = read_credential('LO_GATUS_TOKEN', environ={'LO_GATUS_TOKEN_FILE': credential_mount})
    basic_pair(token)
    require(Path(endpoint_file).is_file(),
            'No Gatus endpoint at ' + endpoint_file + '; the stage run that started this container wrote it '
            'from the Gatus document it mounted, and a probe that guesses the endpoint key files coverage '
            'against an engine it never asked')
    blob = Path(endpoint_file).read_bytes()
    require(len(blob) <= GATUS_ENDPOINT_MAX_BYTES,
            'The Gatus endpoint document at ' + endpoint_file + ' is larger than ' + str(GATUS_ENDPOINT_MAX_BYTES)
            + ' bytes; this stage writes one small url key, so a bigger file is not the one this container '
            'was configured with')
    try:
        endpoint = json.loads(blob.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise ValueError('The Gatus endpoint document at ' + endpoint_file + ' is not readable JSON; the '
                         'stage wrote it, so a damaged copy is a refusal and not something to guess at') from None
    require(isinstance(endpoint, dict) and set(endpoint) == {'url'} and isinstance(endpoint['url'], str),
            'The mounted Gatus endpoint document must hold exactly one url key and nothing else')
    parts = urllib.parse.urlsplit(endpoint['url'])
    require(parts.scheme == 'http' and parts.netloc == GATUS_STATUS_ORIGIN and parts.path == GATUS_STATUS_PATH
            and not parts.query and not parts.fragment,
            'The mounted Gatus endpoint is not the one status route this stage was configured with on ' + GATUS_STATUS_ORIGIN
            + '; a Basic credential is presented to the engine it was minted for, and to no other host')
    return (JsonClient('http://' + GATUS_STATUS_ORIGIN, token, scheme=GATUS_AUTH_SCHEME, allow_http=True,
                       timeout=GATUS_READ_TIMEOUT_SECONDS), parts.path)


def gatus_authentication(credential_mount=GATUS_CREDENTIAL_MOUNT, endpoint_file=GATUS_ENDPOINT_MOUNT):
    """Six bounded real requests; retain status assertions, never credentials or upstream bodies."""
    label = 'configuration'
    try:
        correct, path = gatus_client(credential_mount, endpoint_file)
        user, password = basic_pair(correct.token)

        def pair(name, value):
            return base64.b64encode((name + ':' + value).encode('ascii')).decode('ascii')

        cases = [('correct', correct.token, GATUS_AUTH_SCHEME, 200),
                 ('missing', None, GATUS_AUTH_SCHEME, 401),
                 # bcrypt considers only the first 72 bytes; a suffix can still authenticate.
                 ('wrong_password', pair(user, ('!' if password[0] != '!' else '?') + password[1:]), GATUS_AUTH_SCHEME, 401),
                 ('wrong_user', pair(user + '-incorrect', password), GATUS_AUTH_SCHEME, 401),
                 ('bearer', correct.token, 'Bearer', 401),
                 ('correct_again', correct.token, GATUS_AUTH_SCHEME, 200)]
        statuses = {}
        for label, token, scheme, expected in cases:
            client = JsonClient(correct.base, token, scheme=scheme, allow_http=True,
                                timeout=GATUS_READ_TIMEOUT_SECONDS)
            status, body = client.request('GET', path)
            require(status == expected, 'Unexpected authentication response')
            if expected == 200:
                sample = gatus_sample(body, before=dt.datetime.now(dt.timezone.utc))
                require(sample is not None, 'Authenticated response has no completed Gatus result')
            statuses[label] = status
        return {'status': 'pass', 'checks': statuses}
    except Exception:
        raise RuntimeError('Gatus authentication check failed: ' + label) from None


def empty_notification_sink():
    sink = JsonClient('http://notification-sink:8010', read_credential('LO_NOTIFY_TOKEN'), allow_http=True)
    status, received = sink.request('GET')
    require(status == 200 and isinstance(received, dict) and received.get('receipts') == [],
            'Synthetic stage unexpectedly delivered to the HTTP sink')
    return {'external_receipts': 0, 'synthetic_non_sending': True}


def recorded_recovery(state_path, incident_id):
    """Read one synthetic incident's durable ordered acknowledgements, without writing state."""
    with closing(sqlite3.connect(Path(state_path).resolve().as_uri() + '?mode=ro', uri=True,
                                 timeout=5)) as db:
        db.execute('BEGIN')
        rows = db.execute('SELECT id,status,payload FROM outbox WHERE incident_id=? '
                          'ORDER BY sequence LIMIT 3', (incident_id,)).fetchall()
        require(len(rows) <= 2, 'Synthetic incident has duplicate notification rows')
        if len(rows) != 2 or any(row[1] != 'sent' for row in rows):
            return None
        require(len({row[0] for row in rows}) == 2, 'Synthetic notification IDs are not distinct')
        for row, transition in zip(rows, ('opened', 'resolved')):
            require(len(row[2]) <= 100000, 'Synthetic notification payload exceeds bound')
            payload = json.loads(row[2])
            require(payload['transition'] == transition and payload['incident_id'] == incident_id,
                    'Synthetic notifications are not ordered opened then resolved')
            event = payload['event']
            require(event['source'].startswith('stage-') and event['kind'] == 'availability',
                    'Recovery notification is not a synthetic availability observation')
            reservations = db.execute('SELECT destination,test_window FROM notification_reservations '
                                      'WHERE outbox_id=? LIMIT 101', (row[0],)).fetchall()
            require(0 < len(reservations) <= 100 and all(
                destination in ('recording-sink', 'synthetic-sink') and window is None
                for destination, window in reservations), 'Synthetic delivery used an external route')
            accepted = db.execute("SELECT count(*) FROM notification_attempts WHERE outbox_id=? "
                                  "AND result='accepted'", (row[0],)).fetchone()[0]
            require(accepted == 1, 'Synthetic notification was not acknowledged exactly once')
        return {'recorded_notifications': 2, 'ordered_delivery': True,
                'acknowledged_once': True, 'synthetic_non_sending': True}


def main():
    refuse_optimized()
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['failure', 'recovery', 'restarted', 'backup', 'healthy', 'gatus-auth', 'non-sending'])
    args = parser.parse_args()
    if args.action == 'gatus-auth':
        print(json.dumps(gatus_authentication()))
        return
    if args.action == 'non-sending':
        print(json.dumps({'status': 'pass', **empty_notification_sink()}))
        return
    # security manifests: the role list arrives as the mounted secret file the container was started with, not as
    # an environment value. LO_PLATFORM_CREDENTIALS names it; components/control/platform/compose.yaml
    # sets it, so a container that does not name it is not the manifest's platform.
    credentials = json.loads(Path(os.environ['LO_PLATFORM_CREDENTIALS']).read_text())

    def client(identity):
        token = next(item['token'] for item in credentials if item['identity'] == identity)
        return JsonClient('http://127.0.0.1:8002', token, allow_http=True)
    reader, producer = client('stage-reader'), client('stage-rehearsal')
    gatus, gatus_statuses = gatus_client()
    rule = read_document('/checks/availability.yaml')
    rule['source'] = 'stage-rehearsal'
    if args.action in ('failure', 'recovery', 'healthy'):
        expected = args.action != 'failure'
        deadline = time.monotonic() + 60
        while True:
            now = dt.datetime.now(dt.timezone.utc)
            end = dt.datetime.fromtimestamp(int(now.timestamp()) // 5 * 5, dt.timezone.utc)
            status, body = gatus.request('GET', gatus_statuses)
            sample = gatus_sample(body, before=end) if status == 200 else None
            if sample and sample['value'] == expected and (end - dt.datetime.fromisoformat(sample['observed_at'].replace('Z', '+00:00'))).total_seconds() < 10:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('Gatus did not observe expected synthetic condition')
            time.sleep(1)
        if args.action == 'healthy':
            print(json.dumps({'status': 'healthy', 'gatus': True}))
            return
        require(producer.request('POST', '/v1/evidence', sample)[0] == 200, 'Evidence intake was not accepted')
        values = []
        for item in evaluate(os.environ['LO_INDEX_PATH'], rule, sample, now=now, window_seconds=5):
            status, result = producer.request('POST', '/v1/events', item)
            require(status == 200, 'Event intake rejected: ' + str(result))
            require(producer.request('POST', '/v1/events', item)[1]['status'] == 'duplicate',
                    'Replayed event was not deduplicated')
            values.append(result)
        incident = values[-1]
        if args.action == 'failure':
            require(incident['transition'] == 'opened',
                    'Expected an opened incident, saw ' + str(incident['transition']))
            action = {'retry_key': 'synthetic-rehearsal', 'incident_id': incident['incident_id'], 'action': 'inspect-synthetic', 'version': '1',
                      'targets': [rule['resource_id']], 'parameters': {}, 'evidence': [incident['event_id']],
                      'expires_at': utc_text(now + dt.timedelta(hours=1))}
            status, proposed = client('stage-agent').request('POST', '/v1/actions', action)
            require(status == 200, 'Proposal was not accepted: ' + str(proposed))
            decision = {'action_id': proposed['action_id'], 'decision': 'approved'}
            require(reader.request('POST', '/v1/actions/decision', decision)[0] == 400,
                    'A reader approved an action')
            require(client('stage-agent').request('POST', '/v1/actions/decision', decision)[0] == 400,
                    'The proposing agent approved its own action')
            require(client('stage-operator').request('POST', '/v1/actions/decision', decision)[0] == 200,
                    'The human role could not approve the action')
            require(client('stage-operator').request('POST', '/v1/actions/decision', decision)[0] == 400,
                    'The same action was approved twice')
            status, execution = client('stage-runner').request('POST', '/v1/actions/claim', {'action_id': proposed['action_id']})
            require(status == 200, 'The runner could not claim the approved action')
            again = client('stage-runner').request('POST', '/v1/actions/claim', {'action_id': proposed['action_id']})
            require(again[0] == 400, 'A claimed execution was handed out again')
            # No external operation is dispatched. SIGKILL will simulate an uncertain claim.
            print(json.dumps({'status': 'pass', 'incident_id': incident['incident_id'], 'execution_id': execution['execution_id'],
                              'event_retry': 'duplicate', 'read_agent_approval': 'denied', 'claim': 'single-use'}))
        else:
            require(incident['transition'] == 'resolved',
                    'Expected a resolved incident, saw ' + str(incident['transition']))
            deadline = time.monotonic() + 60
            while True:
                empty_notification_sink()
                recorded = recorded_recovery(os.environ['LO_STATE_PATH'], incident['incident_id'])
                if recorded is not None:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('Synthetic notification recording did not recover')
                time.sleep(1)
            print(json.dumps({'status': 'pass', 'incident_id': incident['incident_id'],
                              'external_receipts': 0, **recorded}))
    elif args.action == 'restarted':
        _, status = reader.request('GET', '/v1/status')
        require(status['actions'].get('unknown') == 1, 'The killed claim is not an unknown action: ' + str(status))
        require(status['incidents'].get('open') == 1, 'The open incident did not survive the restart: ' + str(status))
        _, rows = reader.request('GET', '/v1/records/executions')
        execution = rows['rows'][0]
        require('token_hash' not in execution, 'The execution record leaked a credential hash')
        again = client('stage-runner').request('POST', '/v1/actions/claim', {'action_id': execution['action_id']})
        require(again[0] == 400, 'An interrupted execution was redispatchable')
        require(client('stage-operator').request('POST', '/v1/executions/outcome',
                                                 {'execution_id': execution['id'], 'outcome': 'failed'})[0] == 200,
                'The human role could not reconcile the interrupted execution')
        print(json.dumps({'status': 'pass', 'interrupted_execution': 'unknown; reconciled as no operation dispatched', 'redispatch': 'refused'}))
    else:
        store = Store('/data/platform.db')
        destination = Path('/data/backup-' + str(time.time_ns()) + '.db')
        store.backup(destination)
        restored = Store(destination)
        require(restored.status() == store.status(), 'A restored backup does not reproduce the platform status')
        require(restored.records('events') == store.records('events'),
                'A restored backup does not reproduce the event log')
        require(restored.records('audit') == store.records('audit'),
                'A restored backup does not reproduce the audit log')
        print(json.dumps({'status': 'pass', 'backup': str(destination), 'restore': 'independent SQLite integrity/state/events/audit match'}))


if __name__ == '__main__':
    main()

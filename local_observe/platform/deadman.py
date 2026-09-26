"""External platform-availability witness: probes the platform, reports to a Healthchecks check.

No dependency on platform storage or intake: this process holds a **reader** credential and one ping
URL, and writes nothing inside the system it watches. What changed in job observe standard (decision job observation,
`docs/DECISIONS.md` section H) is the reporting target: the check-in goes to a Healthchecks check
(`components/control/job-observe/CONTRACT.md`) instead of a hand-wired notification channel, so the
deadline is evaluated by a process that is not this one -- and if this process dies, its own silence
is the alarm. The failure clock, the bounded outbox and the incident identity in `tick` are unchanged.
"""
import datetime as dt
import json
import os
from pathlib import Path
import re
import time
from typing import Any
import urllib.error
import urllib.request
import uuid

from local_observe.credentials import read_credential
from local_observe.http import JsonClient, NoRedirect, TransportError
from local_observe.inventory.validation import digest, timestamp, utc_text
from local_observe.log import get_logger
from .detection_worker import save
from .owner import exclusive_owner

log = get_logger(__name__)

# The identity a missed check-in arrives under. `kind` is 'availability' because that is what
# state.validate_event admits: exactly availability/coverage/threshold/drift at this commit. There is
# no 'job' kind, and docs/DECISIONS.md event vocabulary (item event kinds) adds anomaly/security -- not job.
CHECKIN_SOURCE = 'deadman-witness'
CHECKIN_RULE = 'deadman-checkin'
# The evaluation slice stamped on the event. It is a window, not a grace: Healthchecks owns the
# deadline, this only bounds how far a single verdict claims to speak for.
CHECKIN_WINDOW_SECONDS = 60
# An HTTPS ping URL with no userinfo, no query string and no fragment, and no dot-segment in the path
# (the same rule local_observe/http.py applies to a relative path). Deliberately narrower than what
# Healthchecks accepts: a ping URL is a bearer credential, so a redirect target or a query parameter is
# a second destination nobody approved. The documented keyword/body pings (`?msg=`) are therefore
# refused here; the append-`/fail` form (upstream docs/signaling_failures.md) is what this client uses,
# and it needs no query.
PING_URL = re.compile(r'^https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?/[A-Za-z0-9._~/-]+/?$')
PING_URL_ALLOW_HTTP = re.compile(r'^http://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?/[A-Za-z0-9._~/-]+/?$')
MAX_PING_RESPONSE_BYTES = 4096


def checkin_event(*, source: str = CHECKIN_SOURCE, rule_id: str = CHECKIN_RULE,
                  resource_id: str | None, firing: bool, now: dt.datetime,
                  window_seconds: int = CHECKIN_WINDOW_SECONDS) -> dict[str, Any]:
    """Build the canonical availability event one check-in verdict deserves.

    *resource_id* is the declared inventory resource of the job being watched -- the job name as the
    resource, which is what the operator's alert has to name -- or None for the platform-wide witness
    with no declared resource of its own.

    The shape is the product's canonical event, not a private one: the same field set, the same
    `source_event_id` formula as `detections.event`, and evidence that references no query a reader
    cannot run. `tests/test_deadman.py` asserts `state.validate_event` accepts it, which is what keeps
    this independent module honest without importing the storage layer into a process that must not
    need it. The write into platform state is deliberately NOT this module's job: that needs a
    producer credential, and a witness holding one could be silenced by the thing it watches
    (docs/ARCHITECTURE.md 3.5). The event reaches state through the scrape path, or through the pull
    adapter recorded as an open item in the component's CONTRACT.md.
    """
    if not 1 <= window_seconds <= 3600:
        raise ValueError('Check-in event window must be between one second and one hour')
    if resource_id is not None:
        resource_id = str(uuid.UUID(resource_id))          # canonical text, or it is not a resource
    end = dt.datetime.fromtimestamp(int(now.timestamp()) // window_seconds * window_seconds, dt.timezone.utc)
    window = {'start': utc_text(end - dt.timedelta(seconds=window_seconds)), 'end': utc_text(end)}
    version = '1'
    return {
        'schema_version': 1, 'source': source,
        'source_event_id': digest([rule_id, version, resource_id, window]),
        'resource_id': resource_id, 'observed_at': utc_text(now), 'kind': 'availability',
        'severity': 'warning' if firing else 'info', 'data_class': 'internal',
        'evidence': [{'source': source, 'query_type': 'source-heartbeat', 'parameters': {'rule_id': rule_id},
                      'window': window, 'schema_version': 1,
                      'expires_at': utc_text(end + dt.timedelta(days=15))}],
        'rule_id': rule_id, 'rule_version': version, 'window': window, 'condition': rule_id,
        'status': 'firing' if firing else 'resolved'}


class HealthchecksPing:
    """Push client for one Healthchecks check, and the channel `tick` reports transitions through.

    A check's ping URL *is* its credential -- possession marks the job up, and `GET <url>/fail` marks
    it down early -- so the URL arrives as a mounted file (`LO_HEALTHCHECKS_PING_FILE`) and never as
    an environment value, is never logged, and is never written to disk by this client. No
    `Authorization` header is sent: a bearer token here would be a second secret for the same right.
    """

    def __init__(self, ping_url: str, *, allow_http: bool = False, timeout: int = 10,
                 opener: Any = None) -> None:
        """Accept only a bounded endpoint; a malformed one is a boot refusal, not a silent no-op."""
        pattern = PING_URL_ALLOW_HTTP if allow_http else PING_URL
        if not isinstance(ping_url, str) or not pattern.fullmatch(ping_url) or '..' in ping_url:
            raise ValueError('Check-in target must be an HTTPS ping URL with no userinfo, no dot-segment, '
                             'no query and no fragment (set LO_INTERNAL_ALLOW_HTTP=1 only for a '
                             'plaintext endpoint inside the isolated project network)')
        if not 1 <= timeout <= 20:
            raise ValueError('Invalid check-in timeout')
        self._success = ping_url.rstrip('/')
        self._failure = self._success + '/fail'
        self._timeout = timeout
        # NoRedirect: a ping URL that answers 302 would otherwise have its credential forwarded to a
        # host nobody configured. ProxyHandler({}) keeps a corporate proxy from adding one.
        self._opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect())

    def _get(self, url: str) -> int:
        """Send one check-in request and return the status code; the body is never parsed or logged."""
        try:
            with self._opener.open(urllib.request.Request(url, method='GET'), timeout=self._timeout) as response:
                response.read(MAX_PING_RESPONSE_BYTES)
                return response.status
        except urllib.error.HTTPError as exc:
            # 404 means the code in the URL is unknown to Healthchecks -- a restored or rebuilt check,
            # or a copy of the wrong file. It is a refused check-in, not a successful one.
            return exc.code
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning('Check-in endpoint unreachable', extra={'error_class': type(exc).__name__})
            raise TransportError('Check-in endpoint unreachable') from exc

    def check_in(self, healthy: bool) -> int:
        """Report this tick's verdict: the success URL when the platform answered, `/fail` when not."""
        return self._get(self._success if healthy else self._failure)

    def request(self, method: str, path: str = '', payload: dict[str, Any] | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
        """The durable-outbox channel contract, answered by a check-in instead of a chat message.

        `tick` posts a transition and requires an acknowledgement that names the same delivery before
        it drops the item, so a refused or unreachable check-in leaves the exact item pending and it is
        retried -- the same rule the notification channel had. `opened` pings `/fail` (alert now, not
        at the next deadline); `resolved` pings success.
        """
        if method != 'POST' or path or not isinstance(payload, dict):
            raise ValueError('Only bounded check-in reports are supported')
        if payload.get('event', {}).get('data_class') == 'restricted':
            raise ValueError('Restricted payloads are never sent to a check-in endpoint')
        transition = payload.get('transition')
        if transition not in ('opened', 'resolved'):
            raise ValueError('Unknown check-in transition')
        delivery_id = str(uuid.UUID(str(payload.get('delivery_id'))))
        uuid.UUID(str(payload.get('incident_id')))
        if (headers or {}).get('Idempotency-Key') != delivery_id:
            raise ValueError('Check-in identity mismatch')
        code = self._get(self._failure if transition == 'opened' else self._success)
        return code, {'accepted': code == 200, 'delivery_id': delivery_id}


def tick(path: Path | str, healthy: bool, channel: Any, *, now: dt.datetime,
         grace_seconds: int = 120, resource_id: str | None = None,
         source: str = CHECKIN_SOURCE, rule_id: str = CHECKIN_RULE) -> dict[str, Any]:
    """Advance the witness clock one tick and report any transition through *channel*, exactly once.

    The state file holds the failure clock and the pending outbox, so a restart does not restart the
    grace window and a refused report stays queued with its original identity. *channel* may be a
    `HealthchecksPing` or any object with the same `request` contract -- `scripts/rehearse_witness.py`
    and the tests pass a recorder, which is how the witness is exercised with no network and no live
    credential. `resource_id` attributes the event to a declared job; see `checkin_event`.
    """
    if type(healthy) is not bool or not 1 <= grace_seconds <= 3600:
        raise ValueError('Invalid dead-man verdict/grace')
    path = Path(path)
    state = json.loads(path.read_text()) if path.exists() else {
        'last_check': None, 'failed_since': None, 'incident_id': None, 'pending': []}
    if state['last_check'] and timestamp(state['last_check']) > now:
        raise ValueError('Clock moved backward; do not infer recovery')
    state['last_check'] = utc_text(now)
    transition = None
    if healthy:
        state['failed_since'] = None
        if state['incident_id']:
            transition = 'resolved'
    else:
        state['failed_since'] = state['failed_since'] or utc_text(now)
        if not state['incident_id'] and (now - timestamp(state['failed_since'])).total_seconds() >= grace_seconds:
            state['incident_id'] = str(uuid.uuid4())
            transition = 'opened'
    if transition:
        if len(state['pending']) >= 100:
            raise ValueError('Dead-man outbox full; operator inspection required')
        state['pending'].append({
            'delivery_id': str(uuid.uuid4()), 'incident_id': state['incident_id'], 'transition': transition,
            'event': checkin_event(source=source, rule_id=rule_id, resource_id=resource_id,
                                   firing=transition == 'opened', now=now)})
        if transition == 'resolved':
            state['incident_id'] = None
    save(path, state)
    if state['pending']:
        payload = state['pending'][0]
        code, receipt = channel.request('POST', payload=payload, headers={'Idempotency-Key': payload['delivery_id']})
        if code == 200 and receipt.get('accepted') is True and receipt.get('delivery_id') == payload['delivery_id']:
            state['pending'].pop(0)
            save(path, state)
    return {'status': 'unavailable' if state['incident_id'] else ('healthy' if healthy else 'grace'),
            'pending': len(state['pending'])}


def platform_healthy(code: int, body: object) -> bool:
    """Recognise authenticated status independently of the platform's storage schema.

    The status response exposes the database version, not a witness wire version.
    An independent witness must survive database upgrades without being redeployed.
    """
    return (code == 200 and isinstance(body, dict)
            and type(body.get('schema_version')) is int and body['schema_version'] > 0)


def main() -> None:
    """Run the witness: read the two credentials, then probe / check in / record, every 30 seconds.

    Both credentials are mounted files (`LO_HEALTHCHECKS_PING_FILE`, `LO_READER_TOKEN_FILE`); either
    one missing is a `KeyError` out of `read_credential` before the first probe, which is the point --
    the process must not come up unwatched.
    """
    # The ping URL first and the probe second: a witness with no deadline owner is the gap job observation
    # existed to close, so a missing file must stop the process rather than start an unwatched one.
    client = HealthchecksPing(read_credential('LO_HEALTHCHECKS_PING'),
                              allow_http=os.environ.get('LO_INTERNAL_ALLOW_HTTP') == '1')
    resource = os.environ.get('LO_DEADMAN_RESOURCE_ID')
    if resource:
        resource = str(uuid.UUID(resource))
    probe = JsonClient(os.environ['LO_PLATFORM_URL'], read_credential('LO_READER_TOKEN'),
                       ca_file=os.environ.get('LO_PLATFORM_CA_FILE'))
    path = Path(os.environ['LO_DEADMAN_STATE'])
    path.parent.mkdir(parents=True, exist_ok=True)
    with exclusive_owner(path):
        while True:
            healthy = False
            try:
                code, body = probe.request('GET', '/v1/status')
                healthy = platform_healthy(code, body)
            except (TransportError, ValueError, TypeError, AttributeError) as exc:
                log.warning('Dead-man probe could not read platform status', extra={'error_class': type(exc).__name__})
                log.debug('Dead-man probe failed', exc_info=True)
            try:
                client.check_in(healthy)
            except TransportError as exc:
                # The deadline owner is unreachable, so it will see the missing ping and alert. Staying
                # quiet here is the loud case; the tick still records the verdict locally.
                log.warning('Check-in could not be delivered; the deadline owner sees its absence',
                            extra={'error_class': type(exc).__name__})
            try:
                outcome = tick(path, healthy, client, now=dt.datetime.now(dt.timezone.utc),
                               resource_id=resource)
                log.info('Dead-man tick finished',
                         extra={'status': outcome.get('status'), 'pending': outcome.get('pending')})
            except (OSError, ValueError, TypeError) as exc:
                log.warning('Dead-man delivery/state unavailable; inspection required',
                            extra={'error_class': type(exc).__name__})
                log.debug('Dead-man tick failed', exc_info=True)
            time.sleep(30)


if __name__ == '__main__':
    main()

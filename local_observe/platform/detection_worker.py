"""One scoped Gatus rule with a durable pending batch and completed-window cursor.

The window is the adapter's own cadence and it is configurable (`LO_DETECTION_WINDOW_SECONDS`,
5..3600 s, default 5 s — the value the platform stage has always run with). It is bounded by the
same rule `detections.evaluate` applies to its `window_seconds` argument, because a window wider
than a day or narrower than a tick is a misconfiguration that should stop the process rather than
silently change what a `coverage` verdict means. `MINIMUM/MAXIMUM_WINDOW_SECONDS` are the one place
that range is written down; the container healthcheck in components/control/synthetics/compose.yaml
reads the same environment value to derive its staleness bound, so a change to the range moves that
file and this one together.
"""
import datetime as dt
import json
import os
from pathlib import Path
import time
from typing import Any

from local_observe.credentials import read_credential
from local_observe.http import JsonClient, TransportError
from local_observe.inventory.validation import read_document, utc_text
from local_observe.log import get_logger
from .detections import evaluate, gatus_sample, gatus_assertion_samples
from .assertions import condition_mapping
from .state import StateError
from .owner import exclusive_owner

log = get_logger(__name__)


def save(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if os.name != 'nt':
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


MINIMUM_WINDOW_SECONDS = 5
MAXIMUM_WINDOW_SECONDS = 3600
DEFAULT_WINDOW_SECONDS = MINIMUM_WINDOW_SECONDS
#: The authorization scheme this worker presents to the probe engine, and not a style choice: it is
#: the only one the pinned release offers on the route it reads. Named as a constant so a test can pin
#: it against the wire format that release expects, instead of pinning a literal inside `main()`.
GATUS_AUTH_SCHEME = 'Basic'


def window_from_environment(environ: dict[str, str] | None = None) -> int:
    """Return the configured window in seconds; a missing value is the default, a bad one is a refusal.

    Absent or empty means `DEFAULT_WINDOW_SECONDS`, so an operator who sets nothing keeps the
    behaviour the stage ran with. Anything else must be a plain integer inside
    `MINIMUM_WINDOW_SECONDS..MAXIMUM_WINDOW_SECONDS` — a float, a duration string like `30s`, a sign
    or an out-of-range number raises `ValueError` naming the variable, because a silently ignored
    window is a silently wrong coverage bound.
    """
    source = os.environ if environ is None else environ
    text = source.get('LO_DETECTION_WINDOW_SECONDS', '').strip()
    if not text:
        return DEFAULT_WINDOW_SECONDS
    try:
        value = int(text)
    except ValueError as exc:
        raise ValueError(f'LO_DETECTION_WINDOW_SECONDS must be an integer number of seconds, not '
                         f'{text!r}') from exc
    if not MINIMUM_WINDOW_SECONDS <= value <= MAXIMUM_WINDOW_SECONDS:
        raise ValueError(f'LO_DETECTION_WINDOW_SECONDS must be between {MINIMUM_WINDOW_SECONDS} and '
                         f'{MAXIMUM_WINDOW_SECONDS} seconds, not {value}')
    return value


def tick(index_path: Path | str, rule: dict[str, Any], cursor_path: Path | str, gatus: JsonClient,
         platform: JsonClient, *, now: dt.datetime,
         window_seconds: int = DEFAULT_WINDOW_SECONDS) -> str:
    """Close one completed window: build its batch durably, deliver it, then advance the cursor.

    `window_seconds` is bounded exactly as `detections.evaluate` bounds it (5..3600) and defaults to
    the stage's 5 s, so an existing caller that names no window is unchanged.
    """
    if not MINIMUM_WINDOW_SECONDS <= window_seconds <= MAXIMUM_WINDOW_SECONDS:
        raise ValueError('Invalid detection window')
    path = Path(cursor_path)
    state = json.loads(path.read_text()) if path.exists() else {'last_end': None, 'pending': None}
    end = dt.datetime.fromtimestamp(int(now.timestamp()) // window_seconds * window_seconds, dt.timezone.utc)
    if state['pending'] is None and state['last_end'] is not None and state['last_end'] >= utc_text(end):
        return 'idle'
    if state['pending'] is None:
        baseline = dict(rule)
        mapping = None
        if 'assertions' in baseline:
            mapping = condition_mapping(baseline.pop('assertions'))
            if baseline.get('kind') != 'availability':
                raise StateError('Named assertions require an availability rule')
        sample = None
        named = []
        try:
            status, payload = gatus.request('GET')
            if status == 200:
                if mapping is None:
                    sample = gatus_sample(payload, before=end)
                else:
                    sample, named = gatus_assertion_samples(payload, mapping, before=end,
                                                           source=rule['source'], rule_id=rule['id'])
        except (TransportError, ValueError, KeyError, TypeError):
            pass
        events = evaluate(index_path, baseline, sample, now=end, window_seconds=window_seconds)
        for item in events:
            if item['kind'] == 'availability':
                for name, assertion_sample in named:
                    reference = dict(item['evidence'][0])
                    reference['parameters'] = {'rule_id': name, 'sample_id': assertion_sample['sample_id']}
                    item['evidence'].append(reference)
        state['pending'] = {'end': utc_text(end), 'sample': sample, 'events': events}
        if mapping is not None:
            state['pending']['assertion_samples'] = [item for _, item in named]
        save(path, state)
    batch = state['pending']
    if batch['sample']:
        if platform.request('POST', '/v1/evidence', batch['sample'])[0] != 200:
            raise TransportError('Evidence intake refused; pending batch retained')
    for assertion_sample in batch.get('assertion_samples', []):
        if platform.request('POST', '/v1/evidence', assertion_sample)[0] != 200:
            raise TransportError('Assertion evidence refused; pending batch retained')
    for item in batch['events']:
        if platform.request('POST', '/v1/events', item)[0] != 200:
            raise TransportError('Event intake refused; pending batch retained')
    save(path, {'last_end': batch['end'], 'pending': None})
    return 'delivered'


def main() -> None:
    rule = read_document(os.environ['LO_DETECTION_RULE'])
    window = window_from_environment()
    allow_http = os.environ.get('LO_INTERNAL_ALLOW_HTTP') == '1'
    # `GATUS_AUTH_SCHEME` above is the summary; components/control/synthetics/CONTRACT.md names the
    # upstream files it was read from and the one claim that stays UNVERIFIED. The consequence for the
    # operator is one content rule: LO_GATUS_TOKEN_FILE holds base64("<user>:<password>"), so a bearer
    # token left in that file is refused by a closed engine and ignored by an open one.
    gatus = JsonClient(os.environ['LO_GATUS_URL'], read_credential('LO_GATUS_TOKEN'),
                       scheme=GATUS_AUTH_SCHEME, allow_http=allow_http)
    platform = JsonClient(os.environ['LO_PLATFORM_URL'], read_credential('LO_PRODUCER_TOKEN'), allow_http=allow_http)
    cursor = Path(os.environ['LO_DETECTION_CURSOR'])
    cursor.parent.mkdir(parents=True, exist_ok=True)
    with exclusive_owner(cursor):
        while True:
            try:
                result = tick(os.environ['LO_INDEX_PATH'], rule, cursor, gatus, platform,
                              now=dt.datetime.now(dt.timezone.utc), window_seconds=window)
                log.info('Detection tick finished', extra={'result': result})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                log.warning('Detection delivery unavailable; retaining pending batch',
                            extra={'error_class': type(exc).__name__})
                log.debug('Detection tick failed', exc_info=True)
            time.sleep(2)


if __name__ == '__main__':
    main()

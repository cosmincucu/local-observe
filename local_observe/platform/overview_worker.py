"""Publish a bounded summary of an existing job cursor, of the optional model serve and of a rule pack.

One writer, up to three signals: this process is the only thing that publishes `LO_OVERVIEW_PATH`, so
the `jobs` cursor, the `model` observation and — since overview sigma producer — the Sigma measurement triple land in
the
same atomic write (AI integration task 3 asked for a producer for the tile that the Homepage already renders,
and asked for no second writer of the document). Each signal is absent-by-default in its own way: with
no `ai` block the worker touches no socket and publishes `disabled`, which is the absent-by-default
state `minimal` and `standard` live in; with no `sigma_artifacts` key it publishes no `sigma` key at
all, and `platform/overview.py` answers `unknown` with three nulls instead of the healthy zero a rule
pack that was never counted has not earned (portal layout, notification budget).

The configuration document behind `LO_OVERVIEW_CONFIG` carries four keys — `output` (the file this
process writes), `jobs_cursor` (the cursor file to read, never write), `expected_jobs` (the unique job
names that cursor must account for) and the optional `ai` block — plus the optional fifth,
`sigma_artifacts`: one directory of compiled Sigma artifacts. See `sigma_signal` for what it accepts
and what it refuses.
"""
from collections.abc import Sequence
import datetime as dt
import json
import os
from pathlib import Path
import time
from typing import Any
import urllib.parse
import urllib.request

from local_observe.http import NoRedirect
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.log import get_logger
from . import sigma_runner
from .detection_worker import save

log = get_logger(__name__)

# The eight fields of the AI capability manifest, repeated from `local_observe.ai.capability` on
# purpose: the optional package must stay optional for this worker, so it may not import it, and a
# name list that must move in step is pinned by a test instead (`tests/test_ai_component.py`) in the
# same way `docs/CONTRACTS.md` §4's event kinds are.
MODEL_CAPABILITY_FIELDS = ('context_tokens', 'tools', 'json_mode', 'streaming', 'vision', 'parallel',
                           'quant', 'measured_tok_per_s')
MODEL_MAX_AGE_SECONDS = 120
MODEL_MAX_LABEL = 160
HEALTH_MAX_BYTES = 4096
CAPABILITY_MAX_BYTES = 4096
UNKNOWN_CAPABILITY = 'unknown'
#: How many compiled artifacts one tick may read. The bound is on the count; the bytes of each file
#: are bounded by `sigma_runner.ARTIFACT_MAX_BYTES` (map guard and artifact cap), so the worst tick is this many files
#: of
#: that size, and a tick that opened a directory of ten thousand rules would still be a worker killed
#: by its own MemoryMax before it reported anything.
SIGMA_ARTIFACT_MAX = 64
#: The one pattern `sigma_artifacts` is read with. Compiled artifacts are `.json` and nothing else is
#: opened, so a directory that also holds notes, keys or rules in another format contributes nothing.
SIGMA_ARTIFACT_GLOB = '*.json'
#: How long a path or a reason may be on the operator line. `local_observe.log` truncates at 300
#: characters on its own; stating the same number here keeps the bound in the code that relies on it.
LOG_FIELD_MAX = 300


def jobs_signal(path: Path | str, expected: Sequence[str], *,
                now: dt.datetime) -> dict[str, Any]:
    if not expected or len(set(expected)) != len(expected):
        raise ValueError('Explicit unique job names required')
    source = 'Selected jobs ('+str(len(expected))+'); not estate-wide'
    result = {'status': 'unknown', 'value': None, 'observed_at': utc_text(now),
              'max_age_seconds': 120, 'source': source}
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(1048577)
        if len(raw) > 1048576:
            return result
        cursor = json.loads(raw)
        if not isinstance(cursor, dict) or cursor.get('pending') is not None:
            return result
        observed = cursor['last_end']
        age = (now-timestamp(observed)).total_seconds()
        if not 0 <= age <= 120:
            return result
        rows = cursor['jobs']
        if not isinstance(rows, list) or len(rows) != len(expected) or {r['job'] for r in rows} != set(expected):
            return result
        states = [r['status'] for r in rows]
        if any(s not in ('healthy', 'failed', 'stale', 'disabled', 'overrunning') for s in states):
            return result
        return {**result, 'observed_at': observed, 'value': states.count('failed'),
                'status': 'healthy' if all(s == 'healthy' for s in states) else 'degraded'}
    except (OSError, ValueError, TypeError, KeyError):
        return result


def health_ready(url: Any, timeout: Any) -> bool:
    """Ask the model serve's public health endpoint whether the weights are loaded and it is ready.

    `GET /health` is public by upstream design (it performs no API-key check), which is what lets
    this worker observe the serve without holding its credential. It therefore deliberately uses a
    bare urllib opener rather than `local_observe.http.JsonClient`, which requires a bearer token of
    at least 24 characters and would put an AI key in a process that has no business holding one.
    Redirects are refused, proxies are ignored, the body read is bounded, and only an HTTP 200 whose
    JSON body says `{"status": "ok"}` counts as ready: while a model is loading the serve answers 503
    (`components/control/ai/CONTRACT.md`). Anything else -- timeout, TLS failure, a proxy, a body of
    the wrong shape -- is False, which the caller publishes as `unknown` rather than as healthy.
    """
    if (not isinstance(url, str) or not isinstance(timeout, int) or isinstance(timeout, bool)
            or not 1 <= timeout <= 20):
        return False
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        return False
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(urllib.request.Request(url, method='GET'), timeout=timeout) as response:
            raw = response.read(HEALTH_MAX_BYTES + 1)
            if len(raw) > HEALTH_MAX_BYTES or response.status != 200:
                return False
            body = json.loads(raw)
    except (OSError, ValueError):
        return False
    return isinstance(body, dict) and body.get('status') == 'ok'


def capability_ready(path: Any) -> bool:
    """Whether the capability manifest at *path* is readable, complete and carries no `unknown` field.

    `unknown` is not healthy and an unmeasured manifest is not a permission: a serve that answers
    `/health` while nothing has been measured still may not be *used* (a consumer may not rely on a
    capability the manifest does not measure), so the tile says `degraded` and says why, rather than
    going green because a port is open.
    """
    if not isinstance(path, str) or not path.strip():
        return False
    try:
        raw = Path(path).read_bytes()
        if len(raw) > CAPABILITY_MAX_BYTES:
            return False
        document = json.loads(raw)
    except (OSError, ValueError):
        return False
    if not isinstance(document, dict) or document.get('schema_version') != 1:
        return False
    if set(document) - {'schema_version'} != set(MODEL_CAPABILITY_FIELDS):
        return False
    return all(document[name] != UNKNOWN_CAPABILITY for name in MODEL_CAPABILITY_FIELDS)


def model_signal(ai: Any, *, now: dt.datetime) -> dict[str, Any]:
    """Return the `model` observation for one overview tick from the optional AI configuration.

    Four states, and the distinction between them is the whole value of the tile:

    * `disabled` -- no `ai` block in the worker configuration: the component is not deployed.
    * `unknown`   -- deployed and asked, but the serve did not confirm it is ready, or the model
      label is missing or malformed. Unknown is never healthy.
    * `degraded`  -- the serve is ready and the label is present, but the capability manifest is
      unreadable, incomplete or still full of `unknown`: a model nobody may generate with yet.
    * `healthy`   -- ready, labelled, and every capability field carries a measurement.
    """
    result: dict[str, Any] = {'status': 'disabled', 'value': None, 'observed_at': utc_text(now),
                              'max_age_seconds': MODEL_MAX_AGE_SECONDS,
                              'source': 'ai component not deployed'}
    if ai is None:
        return result
    if not isinstance(ai, dict) or not {'health_url', 'model'} <= set(ai):
        return {**result, 'status': 'unknown', 'source': 'ai observation configuration unavailable'}
    label, timeout = ai.get('model'), ai.get('timeout', 3)
    # The same bounded one-line form `local_observe/ai/client.py` requires of LO_AI_MODEL, so an
    # operator can hand one value to the serve, the client and this tile; a label the client would
    # refuse must never be the green thing the portal shows.
    if (not isinstance(label, str) or not 1 <= len(label) <= MODEL_MAX_LABEL
            or label != label.strip() or any(char in label for char in '\r\n\t ')):
        return {**result, 'status': 'unknown', 'source': 'ai model label unavailable'}
    if not health_ready(ai.get('health_url'), timeout):
        return {**result, 'status': 'unknown', 'source': 'model serve health endpoint did not answer'}
    if not capability_ready(ai.get('capability')):
        return {**result, 'status': 'degraded', 'value': label.strip(),
                'source': 'serve ready; capability manifest unmeasured or unreadable'}
    return {**result, 'status': 'healthy', 'value': label.strip(),
            'source': 'serve health endpoint and measured capability manifest'}


def sigma_artifact_paths(configured: Any) -> list[Path]:
    """Resolve the `sigma_artifacts` value into the bounded, sorted artifact list to read.

    The key names **one directory** — the same shape as `output` and `jobs_cursor`, which are also one
    path string each — and the worker globs `*.json` in it, which is how a rule pack arrives: mounted as
    a directory, ordered by name so the same files always produce the same triple. A list of paths is
    refused rather than accepted leniently: two shapes for one key is two ways to configure the tile by
    accident, and `sigma_runner.main()` is given one artifact by env anyway.

    Raises:
        ValueError: naming why this value cannot be read — not a string, not a directory, holding no
            `*.json`, or holding more than `SIGMA_ARTIFACT_MAX` of them. An empty directory is a
            refusal and not a zero: a pack that is not mounted says `unknown`, never "0 rules shipped".
    """
    if not isinstance(configured, str) or not configured.strip():
        raise ValueError('sigma_artifacts must name one directory of compiled artifacts')
    root = Path(configured)
    if not root.is_dir():
        raise ValueError('sigma_artifacts is not a directory')
    paths = sorted(root.glob(SIGMA_ARTIFACT_GLOB))
    if not paths:
        raise ValueError('sigma_artifacts directory holds no compiled artifact')
    if len(paths) > SIGMA_ARTIFACT_MAX:
        raise ValueError(f'sigma_artifacts directory holds {len(paths)} artifacts, above the bound of '
                         f'{SIGMA_ARTIFACT_MAX}')
    return paths


def sigma_signal(artifacts: Any, *, now: dt.datetime) -> dict[str, Any] | None:
    """Return the `sigma` observation for one tick, or None when it must not be published at all.

    One call to the pack's own pair — `sigma_runner.measurement_report` over the artifacts, then
    `measurement_signal` to put that triple in the shape `platform/overview.py` accepts — so the number
    on the operator surface is the number in the runner's startup log line and neither side re-formats
    the sentence. `now` is the tick's timestamp, as in the other two signals.

    None is the honest answer and it is the only way this signal is ever withheld: an unreadable or
    malformed artifact, a wrong-shaped value, an empty directory or one over the 64-artifact bound is
    not a pack with fewer rules and certainly not a quiet pack, so the key is simply absent and the
    reader says `unknown` (portal layout). An absent key and an explicit `null` are that same None without a
    warning — the reading `model_signal` already gives a null `ai` block. Each artifact goes through
    `sigma_runner.artifact()`, which refuses a wrong mapping, a bad checksum or an over-long query, and
    a pack that is only partly readable is refused whole rather than counted from the files that
    survived. Nothing here opens a socket, a database or a subprocess: it is a bounded read of reviewed
    files.
    """
    if artifacts is None:
        return None
    try:
        report = sigma_runner.measurement_report(sigma_artifact_paths(artifacts))
        return sigma_runner.measurement_signal(report, now=now)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        # One line per tick, and it names what was asked for: an operator who sees `Unknown` on the tile
        # should find this line and learn which path refused, not have to diff the config by hand.
        log.warning('Sigma observation not published',
                    extra={'sigma_artifacts': _log_field(artifacts),
                           'reason': _log_field(f'{type(exc).__name__}: {exc}')})
        return None


def _log_field(value: Any) -> str:
    """Render *value* as one bounded, whitespace-collapsed line for a log field; never raises.

    A path from a config document is untrusted input: collapsing it keeps a literal newline in a
    filename from becoming a second operator line, and bounding it keeps a pathological value from
    stretching the record. `local_observe.log` bounds and JSON-escapes it again on the way out.
    """
    text = (value if isinstance(value, str) else repr(value))[:LOG_FIELD_MAX * 4]
    return ' '.join(text.split())[:LOG_FIELD_MAX] or 'unset'


def publish(config: dict[str, Any], *, now: dt.datetime) -> None:
    """Write the whole observation document in one atomic replace, and log the tick once.

    `jobs` and `model` are always published (`disabled`/`unknown` are real answers, not gaps); `sigma`
    joins the document only when `config['sigma_artifacts']` names a readable rule pack, because the
    absence of that key is the state every deployment without a pack lives in and the reader must be
    able to tell it from a measurement.
    """
    output = Path(config['output'])
    signal = jobs_signal(config['jobs_cursor'], config['expected_jobs'], now=now)
    model = model_signal(config.get('ai'), now=now)
    signals: dict[str, Any] = {'jobs': signal, 'model': model}
    sigma = sigma_signal(config.get('sigma_artifacts'), now=now)
    if sigma is not None:
        signals['sigma'] = sigma
    save(output, {'schema_version': 1, 'signals': signals})
    output.chmod(0o644)
    # A published 'unknown' is a real outcome: the source was unreadable, not the worker stuck.
    log.info('Overview published', extra={'status': signal['status'], 'value': signal['value'],
                                         'observed_at': signal['observed_at'],
                                         'model_status': model['status'], 'model_value': model['value'],
                                         'sigma_status': None if sigma is None else sigma['status']})


def main() -> None:
    config = json.loads(Path(os.environ['LO_OVERVIEW_CONFIG']).read_text())
    while True:
        publish(config, now=dt.datetime.now(dt.timezone.utc))
        time.sleep(30)


if __name__ == '__main__':
    main()

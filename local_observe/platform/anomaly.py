"""Light seasonal-baseline anomaly producer: ``median ± k·scaled-MAD`` per seasonal bucket.

Every point is judged against a band its own series learned rather than against a limit somebody
typed into a file. Points are grouped into a seasonal bucket — ``hour_of_day`` (0..23) or
``hour_of_week`` (0..167, bucket 0 aligned to the epoch hour's weekday) — and each bucket learns
``median ± k * 1.4826 * MAD``, the 1.4826 being the consistency constant that turns MAD into a σ
estimate for normal data. Median and MAD over a fixed list of points involve no randomness, so
training is deterministic by construction: ``train(points) == train(points)`` with no seed.

Two limitations stay visible instead of becoming silent guesses:

* a bucket trained on fewer than ``min_per_bucket`` points cannot judge anything — its current
  points are *skipped and reported*, never read as normal;
* a series trained on fewer than ``min_points`` points emits nothing at all, and says why.

The only output is the platform's event factory: one canonical event per series per evaluation
window, ``kind='anomaly'``, severity from how far the worst point sits beyond its band edge, and an
evidence sample holding the value and instant behind that verdict. An anomaly is an *input* to
incidents — it dedups and correlates like any other event and is never a standalone page. This
worker notifies nobody and reads no delivery mode: the page-or-not decision belongs to the platform
service, as it does for every other producer's event.

Series data arrives through ``sigma_runner.ClickHouse``, the same bounded read-only query client the
Sigma runner uses, so this package keeps one HTTP client and one set of server-side bounds; the SQL
is operator-reviewed text, never built from user input. Events go to platform intake with the
producer token, exactly as the other workers post theirs.

What a series has already been told about, and what is still owed to the platform, lives in this
producer's own cursor file (`anomaly_cursor`): each completed window is recorded as **begun**, and the
series is recorded as **having had its turn**, before the store is asked anything about it; its two
request bodies are persisted *before* either is POSTed, and the window is only acknowledged once
**both** answers arrive. A restart therefore resumes at the window the cursor says is next and replays
the bytes it stored rather than asking the store again for a verdict it already made — and a window
whose *read* failed before any payload existed is re-read, because nothing about it was ever promised.
With a coherent cursor retained, a window is judged once; a lost or stale cursor can re-judge one, and
the store's dedup of identical bytes is what keeps that from becoming a second incident — it is not a
repair, and a re-judged window that came out differently is not deduplicated away.

The producer is **off unless ``LO_ANOMALY_CONFIG`` names a JSON file**; with no file named it logs
one INFO line and exits 0, touching nothing. Turning it on means naming a cursor too:
``LO_ANOMALY_CURSOR`` must be an absolute path on a host-local filesystem whose private parent
directory already exists and is reachable through no symlinked ancestor, and a configured producer
with no cursor refuses to start rather than deliver verdicts it cannot re-send. See this package's
README for every knob, what turning each one down costs, and what the cursor does and cannot survive.
"""
import contextlib
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import time
from collections.abc import Iterable, Mapping
from statistics import median
from typing import Any, NamedTuple

from local_observe.credentials import read_credential
from local_observe.http import JsonClient, TransportError
from local_observe.inventory import index
from local_observe.inventory.validation import digest, utc_text
from local_observe.log import get_logger
from . import anomaly_cursor
from .detections import event
from .owner import exclusive_owner
from .sigma_runner import ClickHouse, SERIES_MAX_POINTS
from .state import identifier, label

log = get_logger(__name__)

# Season name -> number of buckets in one full cycle. 3600-second buckets, so hour_of_week needs 168.
SEASONS: dict[str, int] = {'hour_of_day': 24, 'hour_of_week': 168}
BUCKET_SECONDS = 3600
# Scaled MAD is a σ estimate for normally distributed data; without this the same `k` would mean a
# much tighter band than the one a reader assumes.
MAD_SCALE = 1.4826
CONFIG_ENVIRONMENT = 'LO_ANOMALY_CONFIG'
SOURCE_ENVIRONMENT = 'LO_ANOMALY_SOURCE'

DEFAULTS: dict[str, Any] = {'season': 'hour_of_day', 'k': 3.0, 'window_days': 14, 'min_points': 48,
                            'min_per_bucket': 3}
DEFAULT_TICK_SECONDS = 300
# Each bound is a refusal at load, not a runtime surprise. `evaluation_seconds` is the event window
# and `state.validate_event` refuses a window over 7 days, so six days is the honest ceiling.
LIMITS: dict[str, tuple[float, float]] = {'k': (1.0, 20.0), 'window_days': (1, 90),
                                          'min_points': (4, SERIES_MAX_POINTS),
                                          'min_per_bucket': (1, 64), 'tick_seconds': (60, 86400),
                                          'evaluation_seconds': (60, 6 * 86400)}
CONFIG_KEYS = frozenset({'series', 'season', 'k', 'window_days', 'min_points', 'min_per_bucket',
                         'tick_seconds', 'evaluation_seconds'})
SERIES_KEYS = frozenset({'id', 'resource_id', 'sql', 'sql_sha256', 'season', 'k', 'window_days',
                         'min_points', 'min_per_bucket', 'evaluation_seconds',
                         'coverage_unjudgeable_windows'})
SERIES_REQUIRED = ('id', 'resource_id', 'sql', 'sql_sha256')
MAX_SERIES = 16
MAX_CONFIG_BYTES = 1_048_576
MAX_SQL_BYTES = 65_536
# Clauses that would let a hand-written series query leave the store instead of reading it. Sigma's
# SQL comes from a pinned compiler and needs no such list; this one is typed by an operator, and a
# read-only query user is a grant, not a shape — so the shape is refused here as well as denied
# there. A legitimate column whose name collides with one of these has to be aliased in the query.
WRITE_CLAUSES = ('outfile', 's3(', 'url(', 'hdfs(', 'azure(', 'remote(')
# The four ceilings of one catch-up round, explained in :class:`RoundBudget`. They are constants and
# not configuration on purpose; the reasoning for that choice is the class docstring, and README.md
# states the operator-facing cost of each.
MAX_CATCH_UP_WINDOWS = 4
MAX_WINDOWS_PER_ROUND = 16
MAX_QUERIES_PER_ROUND = 16
MAX_POSTS_PER_ROUND = 32
# What `main` repeats out of the round summary, so the one line a service manager keeps carries the
# same set of numbers every time and a reader can grep it.
ROUND_FIELDS = ('result', 'windows', 'queries', 'posts', 'delivered', 'recovered', 'no_verdict',
                'refusals', 'lag_windows', 'pending', 'stale_entries', 'unresolved_pending')
# How loudly each word of a round deserves to be the one reported for a series that did several
# things: a refusal outranks a delivery, a delivery outranks a silent window, and "the round ran out of
# budget" never erases something the series actually did earlier in it.
_LOUDER = {'caught_up': 0, 'deferred': 1, 'idle': 2, 'insufficient': 2, 'unjudgeable': 2,
           'recovered': 3, 'delivered': 4, 'refused': 5}


class BucketStats(NamedTuple):
    """What one seasonal bucket learned: its centre, its spread and how little it saw."""

    median: float
    mad_scaled: float
    count: int


class Baseline(NamedTuple):
    """Trained bands for one series; `insufficient` names the buckets that could not be learned."""

    season: str
    k: float
    min_per_bucket: int
    buckets: dict[int, BucketStats]
    insufficient: tuple[int, ...]


class Deviation(NamedTuple):
    """One current point outside its band; `magnitude` is the distance beyond the edge in MADs.

    A zero-spread (perfectly flat) training bucket gives ``magnitude`` the value ``inf``: any
    movement at all is infinitely far in MAD units, so such a bucket must not read as "normal".
    """

    epoch_s: float
    value: float
    lo: float
    hi: float
    magnitude: float


class SkippedPoint(NamedTuple):
    """A current point no band could judge — counted in the tick line, never read as normal."""

    epoch_s: float
    value: float
    reason: str


class DetectionResult(NamedTuple):
    """Deviations plus the visibly-skipped current points (an unpackable pair)."""

    deviations: list[Deviation]
    skipped: list[SkippedPoint]


def bucket_of(season: str, epoch_s: float) -> int:
    """Return the seasonal bucket index that *epoch_s* (UTC epoch seconds) falls in."""
    if season not in SEASONS:
        raise ValueError(f'Unknown anomaly season: expected one of {", ".join(sorted(SEASONS))}')
    return int(epoch_s // BUCKET_SECONDS) % SEASONS[season]


def train(points: list[tuple[float, float]], *, season: str = 'hour_of_day',
          min_per_bucket: int = 3, k: float = 3.0) -> Baseline:
    """Learn one ``median ± k·scaled-MAD`` band per seasonal bucket from ``(epoch_s, value)`` points.

    Thin buckets keep their statistics but are named in `Baseline.insufficient` and are refused by
    :func:`band` — a baseline with three samples must not pretend to know a weekday night. An empty
    point list yields no buckets, so every :func:`band` call returns None and nothing is judged.
    """
    if season not in SEASONS:
        raise ValueError(f'Unknown anomaly season: expected one of {", ".join(sorted(SEASONS))}')
    if not 1 <= min_per_bucket <= 64 or not math.isfinite(k) or not 1.0 <= k <= 20.0:
        raise ValueError('Anomaly training parameters are outside their bounds')
    grouped: dict[int, list[float]] = {}
    for epoch_s, value in points:
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
            raise ValueError('Anomaly training values must be finite numbers')
        grouped.setdefault(bucket_of(season, epoch_s), []).append(float(value))
    buckets: dict[int, BucketStats] = {}
    insufficient: list[int] = []
    for bucket in sorted(grouped):
        values = grouped[bucket]
        centre = float(median(values))
        spread = MAD_SCALE * float(median([abs(value - centre) for value in values]))
        buckets[bucket] = BucketStats(median=centre, mad_scaled=spread, count=len(values))
        if len(values) < min_per_bucket:
            insufficient.append(bucket)
    return Baseline(season=season, k=k, min_per_bucket=min_per_bucket, buckets=buckets,
                    insufficient=tuple(insufficient))


def band(baseline: Baseline, epoch_s: float) -> tuple[float, float] | None:
    """Return the learned ``(lo, hi)`` at *epoch_s*, or None when that bucket cannot judge.

    None means *cannot judge* and never *normal*: the caller must treat it as a skipped point.
    """
    stats = baseline.buckets.get(bucket_of(baseline.season, epoch_s))
    if stats is None or stats.count < baseline.min_per_bucket:
        return None
    delta = baseline.k * stats.mad_scaled
    return (stats.median - delta, stats.median + delta)


def detect(baseline: Baseline, points: list[tuple[float, float]]) -> DetectionResult:
    """Flag every point outside its bucket band and report every point the band could not cover."""
    deviations: list[Deviation] = []
    skipped: list[SkippedPoint] = []
    for epoch_s, value in points:
        learned = band(baseline, epoch_s)
        if learned is None:
            skipped.append(SkippedPoint(
                epoch_s=epoch_s, value=value,
                reason=f'bucket {bucket_of(baseline.season, epoch_s)} ({baseline.season}) holds '
                       f'fewer than {baseline.min_per_bucket} training points'))
            continue
        lo, hi = learned
        if lo <= value <= hi:
            continue
        stats = baseline.buckets[bucket_of(baseline.season, epoch_s)]
        distance = (lo - value) if value < lo else (value - hi)
        # Zero spread is perfect surprise: any movement is infinitely far in MAD units.
        magnitude = distance / stats.mad_scaled if stats.mad_scaled > 0 else math.inf
        deviations.append(Deviation(epoch_s=epoch_s, value=value, lo=lo, hi=hi, magnitude=magnitude))
    return DetectionResult(deviations=deviations, skipped=skipped)


def severity_for(deviation: Deviation, baseline: Baseline) -> str:
    """Return the severity a deviation earns: `critical` once it is another ``k`` MADs out.

    The band edge already sits ``k`` scaled-MADs from the bucket median, so a point at
    ``magnitude == k`` is twice as far out as the threshold that flagged it — "the baseline says
    this is odd" against "the baseline says this is nowhere near its own history". ``inf`` (a flat
    training bucket) is `critical` by the same rule. The storm guard is not the severity: repeated
    deviations share one condition key, so they fold into the incident the first one opened.
    """
    return 'critical' if deviation.magnitude >= baseline.k else 'warning'


def worst(deviations: list[Deviation]) -> Deviation:
    """Return the deviation with the largest magnitude, the one the verdict and severity name."""
    return max(deviations, key=lambda item: item.magnitude)


def _bounded_number(name: str, value: Any) -> float:
    """Return *value* as a float inside its documented limit, refusing anything else."""
    low, high = LIMITS[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f'Anomaly configuration {name} must be a finite number')
    if not low <= value <= high:
        raise ValueError(f'Anomaly configuration {name} is outside its allowed range')
    return float(value)


def _reviewed_sql(series_id: str, value: Any, checksum: Any) -> str:
    """Return the SQL text a series may run, or refuse: bounded, bounded-query, reviewed.

    The checksum is checked against the text in the same file, exactly as the compiled Sigma
    artifact does: it catches a truncated or hand-altered config rather than an attacker, who could
    change both fields. The shape checks are the load-bearing part — the two parameter placeholders
    are what keep the operator's own SELECT inside the window this producer asks for, a query that
    ends in anything but ``FORMAT JSON`` cannot be parsed by the shared client at all, and
    :data:`WRITE_CLAUSES` refuses the ways a read turns into a write or an egress. Every message
    names the series id and the offending clause, never the query text.
    """
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= MAX_SQL_BYTES:
        raise ValueError(f'Anomaly series {series_id}: sql must be bounded text')
    if not isinstance(checksum, str) or len(checksum) != 64 or ';' in value:
        raise ValueError(f'Anomaly series {series_id}: sql must be one statement with a 64-hex checksum')
    collapsed = ' '.join(value.lower().split())
    found = [clause for clause in WRITE_CLAUSES if clause in collapsed]
    if found:
        raise ValueError(f'Anomaly series {series_id}: sql uses a clause this producer will not run '
                         f'({", ".join(found)})')
    if '{start_s:' not in value or '{end_s:' not in value:
        raise ValueError(f'Anomaly series {series_id}: sql must bound itself with '
                         f'{{start_s:UInt64}} and {{end_s:UInt64}}')
    if not value.rstrip().upper().endswith('FORMAT JSON'):
        raise ValueError(f'Anomaly series {series_id}: sql must end with FORMAT JSON')
    try:
        normalised = bytes.fromhex(checksum)
    except ValueError:
        raise ValueError(f'Anomaly series {series_id}: sql_sha256 is not hexadecimal') from None
    if hashlib.sha256(value.encode()).digest() != normalised:
        raise ValueError(f'Anomaly series {series_id}: sql_sha256 does not match the sql in this file')
    return value


def _resolve_series(entry: Any, defaults: dict[str, Any], *, seen: set[str]) -> dict[str, Any]:
    """Return one series with every knob resolved, refusing anything the producer will not use."""
    if not isinstance(entry, dict) or set(entry) - SERIES_KEYS or not set(SERIES_REQUIRED) <= set(entry):
        raise ValueError('Anomaly series holds unknown or missing configuration')
    series_id = entry['id']
    if not isinstance(series_id, str):
        raise ValueError('Anomaly series id is not a bounded identifier')
    try:
        label(series_id)
        label('anomaly.' + series_id)
        identifier(entry['resource_id'])
    except ValueError:
        raise ValueError('Anomaly series id or resource_id is not a valid identity') from None
    if series_id in seen:
        raise ValueError(f'Anomaly series {series_id}: repeated series id')
    seen.add(series_id)
    season = entry.get('season', defaults['season'])
    if season not in SEASONS:
        raise ValueError(f'Anomaly series {series_id}: season must be one of {", ".join(sorted(SEASONS))}')
    resolved: dict[str, Any] = {'id': series_id, 'resource_id': entry['resource_id'], 'season': season,
                                'sql_sha256': entry['sql_sha256']}
    for name in ('k', 'window_days', 'min_points', 'min_per_bucket', 'evaluation_seconds'):
        resolved[name] = _bounded_number(name, entry.get(name, defaults[name]))
    resolved['sql'] = _reviewed_sql(series_id, entry['sql'], entry['sql_sha256'])
    threshold = anomaly_cursor.coverage_threshold(entry)
    if threshold:
        label('anomaly-coverage.' + series_id)
        resolved['coverage_unjudgeable_windows'] = threshold
    if resolved['evaluation_seconds'] >= resolved['window_days'] * 86400:
        raise ValueError(f'Anomaly series {series_id}: evaluation window leaves no points to train on')
    return resolved


def load_config(path: Path | str) -> dict[str, Any]:
    """Read and validate ``LO_ANOMALY_CONFIG``; every refusal names a field, never a value.

    Raises `ValueError` rather than falling back to a smaller configuration: a producer that quietly
    dropped the series it could not parse would report "no anomalies" for a signal it never read.
    """
    candidate = Path(path)
    with candidate.open('rb') as stream:
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError(f'{CONFIG_ENVIRONMENT} document exceeds {MAX_CONFIG_BYTES} bytes')
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ValueError(f'{CONFIG_ENVIRONMENT} is not JSON') from None
    if not isinstance(document, dict) or set(document) - CONFIG_KEYS or not isinstance(
            document.get('series'), list) or not 1 <= len(document['series']) <= MAX_SERIES:
        raise ValueError(f'Anomaly configuration needs a series list of 1..{MAX_SERIES} and no '
                         'unknown keys')
    tick_seconds = _bounded_number('tick_seconds', document.get('tick_seconds', DEFAULT_TICK_SECONDS))
    defaults = {name: _bounded_number(name, document[name]) if name in document else DEFAULTS[name]
                for name in ('k', 'window_days', 'min_points', 'min_per_bucket')}
    defaults['season'] = document.get('season', DEFAULTS['season'])
    defaults['evaluation_seconds'] = _bounded_number(
        'evaluation_seconds', document.get('evaluation_seconds', tick_seconds))
    seen: set[str] = set()
    series = [_resolve_series(entry, defaults, seen=seen) for entry in document['series']]
    return {'tick_seconds': tick_seconds, 'series': series}


def producer_config(environment: Mapping[str, str] | None = None) -> dict[str, Any] | None:
    """Return the validated configuration, or None when the producer is not configured at all.

    An unset or blank ``LO_ANOMALY_CONFIG`` is the documented off switch and answers one INFO line
    naming the variable — the same "off is an outcome, not a silence" rule the other workers follow.
    A named file that does not parse is not off: it raises, and `main` exits 1 on it.
    """
    environ = os.environ if environment is None else environment
    raw = (environ.get(CONFIG_ENVIRONMENT) or '').strip()
    if not raw:
        log.info('Anomaly producer is off; no configuration named', extra={'variable': CONFIG_ENVIRONMENT})
        return None
    return load_config(raw)


# The column aliases a reviewed series query must answer with. ``FORMAT JSON`` returns one object per
# row keyed by the selected names, so the pair is resolved by name and a row keyed by anything else
# is refused rather than read positionally.
SERIES_ALIASES = frozenset({'ts', 'v'})


def _series_row(row: Any) -> tuple[float, float]:
    """Return the ``(ts, v)`` pair one series answer row carries, or refuse that row.

    The store answers ``FORMAT JSON`` with an object per row, so ``{'v': 11.0, 'ts': 100}`` is the
    same point as the other order and is resolved by alias name, never by position. Exactly these two
    keys: an extra column is not the query this producer reviewed, and a missing one leaves either no
    instant or no value to judge. The two-number list stays accepted for callers that already hold
    their points as pairs.

    Numbers are taken as they arrived. A value the store answers as text — a quoted ``UInt64``, a
    ``Decimal`` — is refused, not coerced: widening the accepted types is a contract with its own
    review, not a permissive read at the last moment before the maths.
    """
    if isinstance(row, Mapping):
        if set(row) != SERIES_ALIASES:
            raise ValueError('Anomaly series rows must carry exactly the ts and v aliases')
        fields: tuple[Any, Any] = (row['ts'], row['v'])
    elif isinstance(row, list) and len(row) == 2:
        fields = (row[0], row[1])
    else:
        raise ValueError('Anomaly series rows must be ts/v objects or two-number lists')
    if any(isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item)
           for item in fields):
        raise ValueError('Anomaly series rows must be two finite numbers')
    return float(fields[0]), float(fields[1])


def series_points(rows: Any, *, start_s: int, end_s: int) -> list[tuple[float, float]]:
    """Return ``(epoch_s, value)`` pairs from a bounded series answer, refusing anything else.

    Two finite numbers per row and every timestamp inside the window that was asked for: a query
    that ignores its own bounds is a broken query, not a wider baseline. Rows are the ``ts``/``v``
    objects the reviewed SQL's ``FORMAT JSON`` answer decodes to, or two-number lists; see
    :func:`_series_row` for what each row may look like.
    """
    if not isinstance(rows, list) or len(rows) > SERIES_MAX_POINTS:
        raise ValueError('Anomaly series answer is not a bounded row list')
    points: list[tuple[float, float]] = []
    for row in rows:
        epoch_s, value = _series_row(row)
        if not start_s <= epoch_s < end_s:
            raise ValueError('Anomaly series returned a point outside the window it was given')
        points.append((epoch_s, value))
    return points


class RoundBudget:
    """What one round may spend, and why these four numbers are not configuration.

    Before the cursor existed, a producer that had been down for a week had exactly one way to find
    out: it judged the newest window and never mentioned the gap. Catch-up is what changed here, and
    these ceilings are what keep an outage recovery from becoming a query storm against the store and
    an event storm against intake:

    * ``windows`` — the window attempts of the round, **pending retries included**. A round is at most
      this much work whatever the backlog says, and a series whose delivery the platform keeps
      refusing cannot spend the whole round on nothing.
    * ``queries`` — a fresh window costs at most one bounded 2 000-row read and a replay costs none,
      so `windows` can never imply more reads than this.
    * ``posts`` — two per window with a verdict (evidence, then the event), so a round that delivered
      every window it attempted made exactly this many requests and cannot start another.
    * :data:`MAX_CATCH_UP_WINDOWS` is the per-series depth of that rotation, applied in :func:`tick`.

    A caller may pass a **smaller** budget — the tests reach exhaustion with three series instead of
    sixteen — but not a larger one: these ceilings are the load bound that README.md's log-volume row
    and the store's own 2 000-row cap were written against, and a caller able to raise them would make
    that arithmetic false. `main` uses the shipped defaults, so a wider round means editing the code on
    a branch, which is the point.
    """

    def __init__(self, *, windows: int = MAX_WINDOWS_PER_ROUND, queries: int = MAX_QUERIES_PER_ROUND,
                 posts: int = MAX_POSTS_PER_ROUND) -> None:
        for name, value, ceiling in (('windows', windows, MAX_WINDOWS_PER_ROUND),
                                     ('queries', queries, MAX_QUERIES_PER_ROUND),
                                     ('posts', posts, MAX_POSTS_PER_ROUND)):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= ceiling:
                raise ValueError(f'Anomaly round {name} budget is outside its allowed 0..{ceiling}')
        self.limits: dict[str, int] = {'windows': windows, 'queries': queries, 'posts': posts}
        self.used: dict[str, int] = {'windows': 0, 'queries': 0, 'posts': 0}

    def left(self, name: str) -> int:
        return self.limits[name] - self.used[name]

    def can(self, name: str, count: int = 1) -> bool:
        """Report whether *count* units of *name* are still affordable, without spending them."""
        return self.left(name) >= count

    def take(self, name: str) -> bool:
        """Spend one unit of *name*, or decline quietly: the caller decides what the shortage means."""
        if not self.can(name):
            return False
        self.used[name] += 1
        return True


class Verdict(NamedTuple):
    """One window's answer before anything is sent: the word, the log detail, and the payloads.

    `outcome` is the acknowledgement word (`delivered`, `recovered`, `idle`, `insufficient`,
    `unjudgeable`), so what was judged and what was acked cannot drift apart. `sample` and `finding`
    are the two bodies the cursor keeps for a verdict that has something to say; both are None for a
    window that has nothing to say, which is also what makes a no-verdict window cheap to advance.
    """

    outcome: str
    window: dict[str, str]
    detail: dict[str, Any]
    sample: dict[str, Any] | None
    finding: dict[str, Any] | None


def _verdict_binding(series: Mapping[str, Any]) -> str:
    """Return the digest of everything a delivered verdict is a statement about, for one series.

    This is the verdict's own identity and it is deliberately **not** the cursor's series binding:
    it feeds ``rule_version``, ``sample_id`` and therefore ``source_event_id``, so changing it would
    re-key every event already stored. :func:`anomaly_cursor.series_binding` adds the series identity
    (`id`, `resource_id`) on top of the same knobs, because a cursor entry has to know which series it
    belongs to while an event never needed to.

    It is one function and not two copies because the replay preflight has to be able to recompute the
    exact ``rule_version`` the current configuration would produce for a batch it is about to replay:
    a second spelling of this list would be a second opinion about what a verdict means.
    """
    return digest([series['sql_sha256'], series['season'], series['k'], series['window_days'],
                   series['min_points'], series['min_per_bucket'], series['evaluation_seconds']])


def _rule_version(series: Mapping[str, Any]) -> str:
    """Return the ``rule_version`` one verdict of *series* carries: the first 16 hex of its binding."""
    return _verdict_binding(series)[:16]


def _verdict(series: dict[str, Any], query: ClickHouse, *, end_s: int, source: str) -> Verdict:
    """Read and judge one window named by its end instant; nothing here touches the platform.

    `end_s` comes from the cursor and not from the clock: it is the oldest window this series still
    owes. The training span deliberately excludes the evaluated tail — a baseline trained on the points
    it is judging widens its own band around a sustained shift instead of reporting it — and the read
    stays bounded to ``end_s - window_days .. end_s``, the same bounds one current-window tick used, so
    judging an older window is not a licence to widen a query.

    A verdict that has something to say returns **both** bodies; a verdict that has nothing to say
    returns neither, and it is that pair which the cursor persists before either is sent.
    """
    evaluation = int(series['evaluation_seconds'])
    end = dt.datetime.fromtimestamp(end_s, dt.timezone.utc)
    start = end - dt.timedelta(seconds=evaluation)
    query_start = end - dt.timedelta(days=series['window_days'])
    bounds = {'start_s': int(query_start.timestamp()), 'end_s': int(end.timestamp())}
    points = series_points(query.series(series['sql'], bounds), start_s=bounds['start_s'],
                           end_s=bounds['end_s'])
    window = {'start': utc_text(start), 'end': utc_text(end)}
    training = [point for point in points if point[0] < start.timestamp()]
    current = [point for point in points if point[0] >= start.timestamp()]
    detail = {'points': len(points), 'training_points': len(training), 'current_points': len(current)}
    if len(training) < series['min_points']:
        return Verdict('insufficient', window, {**detail, 'min_points': int(series['min_points'])},
                       None, None)
    if not current:
        return Verdict('idle', window, detail, None, None)
    baseline = train(training, season=series['season'], min_per_bucket=int(series['min_per_bucket']),
                     k=series['k'])
    result = detect(baseline, current)
    detail.update({'deviations': len(result.deviations), 'skipped': len(result.skipped),
                   'buckets_insufficient': len(baseline.insufficient)})
    if len(result.skipped) == len(current):
        return Verdict('unjudgeable', window, detail, None, None)
    observed = worst(result.deviations) if result.deviations else None
    newest = max(current, key=lambda item: item[0])
    sample_at, sample_value = (observed.epoch_s, observed.value) if observed else newest
    binding = _verdict_binding(series)
    rule = 'anomaly.' + series['id']
    version = _rule_version(series)
    sample = {'sample_id': digest([binding, window, sample_at, sample_value]),
              'observed_at': utc_text(dt.datetime.fromtimestamp(sample_at, dt.timezone.utc)),
              'ok': True, 'value': sample_value}
    finding = event(source, series['resource_id'], rule, 'anomaly', 'firing' if observed else 'resolved',
                    window, {'rule_id': rule, 'sample_id': sample['sample_id']},
                    query_type='metric-threshold', version=version,
                    severity=severity_for(observed, baseline) if observed else None)
    return Verdict('delivered' if observed else 'recovered', window, detail, sample, finding)


def _coverage_delivery(series, verdict, status, source):
    rule = 'anomaly-coverage.' + series['id']
    version = anomaly_cursor.coverage_version(series)
    sample = {'sample_id': digest([rule, version, verdict.window, status]),
              'observed_at': verdict.window['end'], 'ok': True,
              'value': 1 if status == 'firing' else 0}
    finding = event(source, series['resource_id'], rule, 'coverage', status, verdict.window,
                    {'rule_id': rule, 'sample_id': sample['sample_id']},
                    query_type='metric-threshold', version=version)
    return sample, finding


def _deliver(platform: JsonClient, pending: Mapping[str, Any], *, budget: RoundBudget) -> None:
    """POST a persisted batch in its stored order, or raise with the batch still owed.

    The payloads are the ones :func:`anomaly_cursor.begin` stored, so this is the same request the
    previous process intended: `JsonClient` re-serialises them with the one serializer every request
    here uses, and the platform's own dedup turns a re-send of accepted bytes into one row rather than
    a second incident — which is a property of identical bytes only, and is not a repair available to
    a producer that re-judged a window into something different.

    Both slots are reserved before the first request — posting the evidence and only then finding there
    is no room for the event would spend a round on a half delivery the next round has to repeat
    anyway. A batch always holds both bodies (:func:`anomaly_cursor.begin` refuses less), so the
    reservation is two for schema 1 and two per delivery for schema 2 (at most four).
    """
    if 'deliveries' in pending:
        if not budget.can('posts', 2 * len(pending['deliveries'])):
            raise TransportError('Anomaly round budget spent; this window stays pending')
        for delivery in pending['deliveries']:
            _deliver(platform, delivery, budget=budget)
        return
    sample, finding = pending['sample'], pending['event']
    if not budget.can('posts', 2):
        raise TransportError('Anomaly round budget spent; this window stays pending')
    budget.take('posts')
    if platform.request('POST', '/v1/evidence', sample)[0] != 200:
        raise TransportError('Anomaly evidence refused; this window is not durable')
    budget.take('posts')
    if platform.request('POST', '/v1/events', finding)[0] != 200:
        raise TransportError('Anomaly intake refused; this window is not durable')


def _require_declared(index_path: Path | str, series_list: Iterable[Mapping[str, Any]]) -> None:
    """Refuse a whole round when any configured resource is undeclared, before any read or write.

    Identity is not something a partial verdict may be built on — the same rule `configdrift` applies
    to its artifacts — so one undeclared series stops the round rather than costing the other series
    their windows. Doing it once here, up front, is also what keeps the refusal free of side effects:
    nothing is queried and no cursor byte is written when it fires.
    """
    with index.readonly(index_path) as connection:
        for series in series_list:
            if index.resolve(connection, resource_id=series['resource_id'])['status'] != 'resolved':
                raise ValueError('Undeclared resource')


def _require_bindings(series_list: list[dict[str, Any]], document: Mapping[str, Any], *,
                      source: str, now: dt.datetime) -> None:
    """Preflight every configured entry against the resolved configuration, before the round spends.

    Two things are checked here for **every** configured series the cursor holds an entry for, and
    neither of them is an opaque-hash comparison:

    * the entry's binding still describes this series (identity, the reviewed SQL pin, every knob);
    * every window position the entry holds — `last_acked_end`, `anchored_at`, `owed_end` — is a whole
      second and a whole number of *this series'* configured evaluations from the epoch, and an owed
      attempt sits exactly one evaluation after the last ack. These apply whether or not the entry
      holds a payload: the entry with no payload is the one a failed **read** leaves behind, and an
      owed position two hours past the last ack is a round that would acknowledge the later window and
      skip the hour in between without ever naming it;
    * if the entry owes a batch, that batch is still the batch *this* configuration would have sent —
      rule, resource, version, evidence query kind and parameters, window length, alignment, and its
      position exactly one evaluation after the last acknowledged window, with the platform's own
      ``validate_event`` over the whole shape. See
      :func:`anomaly_cursor.replay_coherent` for what each refusal means.

    Doing it before the round's first query is what makes the refusal have nothing to undo: no read,
    no POST, no cursor byte — the same shape as :func:`_require_declared`, and the property an
    operator needs, because fixing the configuration or the document and rerunning cannot leave a
    half-applied change behind. Discovering a stale batch mid-round would be worse in kind: the round
    would have already POSTed a verdict made from configuration that no longer exists.

    Entries whose series left the configuration are not preflighted against absent configuration; they
    keep their bytes, are structurally validated by ``load``, and are reported in `stale_entries`.

    The cost is stated with the benefit: one mistyped knob in one series holds every other series'
    windows until it is fixed, and the refusal names the series so the fix is not a search.
    """
    for series in series_list:
        entry = document['series'].get(series['id'])
        if entry is not None:
            anomaly_cursor.replay_coherent(series, entry, source=source, now=now,
                                           rule_version=_rule_version(series))


def _next_end(series: dict[str, Any], state: Mapping[str, Any] | None, now_s: float) -> int | None:
    """Return the one window *series* owes next, or None when the cursor says it is caught up.

    An entry that has never acknowledged, begun or owed anything is treated as new even when the file
    already holds it (a round that failed its own write can leave one), and a new series is anchored at
    **its own newest completed window** — the durable anomaly cursor's first-start rule, deliberately not inherited from
    or compared against what a sibling owes. There is no shared-horizon, backfill or join-depth policy
    in this producer: a series is configured to watch from now, not to be handed somebody else's
    backlog, and the anchor WARNING is what says out loud that its earlier history was never judged.
    """
    evaluation = int(series['evaluation_seconds'])
    begun = (state is not None and (state['last_acked_end'] is not None
                                    or state['owed_end'] is not None
                                    or state['pending'] is not None))
    if begun:
        return anomaly_cursor.next_window_end(state, now_s=now_s, evaluation=evaluation)
    return anomaly_cursor.align_end(now_s=now_s, evaluation=evaluation)


def _owed(series_list: list[dict[str, Any]], document: Mapping[str, Any], *,
          now_s: float) -> list[tuple[dict[str, Any], int | None]]:
    """Return ``(series, next window it owes)`` in **durable round-robin order**; None means caught up.

    Three rules, and the order of precedence is the whole point of this function:

    1. **whose turn it is.** :func:`anomaly_cursor.rotation` reads the cursor's ``last_served`` marker
       and starts the list after the series that was last given an attempt, then wraps. The marker is
       written *before* the attempt is made (that is :func:`anomaly_cursor.serve`, one fsync shared
       with the owed-window write), so a process that dies mid-window leaves the turn consumed and
       the next process continues the rotation rather than restarting it. Nothing here is in memory.
    2. **what each series owes.** :func:`anomaly_cursor.next_window_end` — pending batch first, then
       the attempt begun and never acknowledged, then one window past the last acknowledgement.
       Per-series windows stay ascending, contiguous and derived from the file, never from the clock.
    3. **what a series the file has never seen owes** — **its own newest completed window**, the
       first-start rule of the durable anomaly cursor, asked and answered per series with no reference to what a sibling
       owes. There is deliberately no shared-horizon, backfill or join-depth policy here: a series is
       configured to watch from now, and the anchor WARNING is what says its earlier history was never
       judged.

    Oldest-owed-window-first is deliberately **not** the primary key, and that is a correction rather
    than a style choice. A permanently refused series owes the *same* window forever, so any ordering
    that leads with time puts that refusal at the front of every round and every restart and starves
    every series behind it — which is what this producer did before the marker existed, and sorting on
    refusal counts alone does not fix it either: two series owing *different* windows never tie, so the
    older debt still wins forever. Time therefore ranks nothing across series; a name does. Under the
    shipped budget a round can reach all :data:`MAX_SERIES` configured series, and under a budget of
    one window each series is served within ``MAX_SERIES`` rounds whatever its backlog looks like
    beside its neighbours'.
    """
    named = [series['id'] for series in series_list]
    by_id = {series['id']: series for series in series_list}
    owed: list[tuple[dict[str, Any], int | None]] = []
    for series_id in anomaly_cursor.rotation(document, named):
        series = by_id[series_id]
        owed.append((series, _next_end(series, document['series'].get(series_id), now_s)))
    return owed


def _pending_outcome(pending: Mapping[str, Any]) -> str:
    """Return the acknowledgement word a stored batch earns: its own event says which verdict it was."""
    if 'deliveries' in pending:
        return ('delivered' if any(item['event']['status'] == 'firing'
                                   for item in pending['deliveries']) else 'recovered')
    return 'delivered' if pending['event']['status'] == 'firing' else 'recovered'


def _step(series: dict[str, Any], query: ClickHouse, platform: JsonClient,
          document: dict[str, Any], path: Path, *, end_s: int, budget: RoundBudget,
          now: dt.datetime, source: str) -> str:
    """Judge, deliver and acknowledge the one window *end_s* of one series, and log exactly one line.

    The order inside is what the card exists for, and nothing here may be reordered:

    1. the series **takes its turn** (the durable ``last_served`` marker) and, for a fresh window, the
       window is **recorded as owed** — both in one write, on disk **before the store is asked
       anything**, so a read that fails leaves a trace and the same window is owed again however far
       the clock has moved; then it is read and judged, and its two payloads go into the cursor and are
       **fsynced before any request leaves the process**; a window with nothing to say is acked
       straight away;
    2. both payloads are POSTed — the ones the cursor holds, whether they are new or owed from before
       (a replay writes the turn marker first, for the same price and the same reason);
    3. only then is the window acknowledged and the cursor written again.

    So a crash or a refusal at any point replays the same window — with the same bytes when there were
    bytes to send, and with a fresh read when nothing had ever been promised — a refusal leaves the
    cursor position untouched, and a window the platform never accepted is never called delivered.
    Raising leaves the cursor as it was (except the turn marker and the owed window, which are meant to
    survive), which is what the caller's refusal path depends on; a save that fails aborts the attempt
    before anything is posted, so this function never sends a request on the strength of a write that
    did not succeed. ``deferred`` comes back without a log line when the round has nothing left to
    spend, because the caller decides whether that shortage is this series' only line of the round.
    """
    evaluation = int(series['evaluation_seconds'])
    state = anomaly_cursor.ensure_entry(document, series)
    # A pending envelope reserves every pair. An open coverage episode may recover alongside an
    # anomaly, so reserve four for that fresh window; otherwise at most two are needed.
    owed = state['pending']
    post_slots = (2 * len(owed['deliveries']) if owed and 'deliveries' in owed else
                  4 if anomaly_cursor.coverage_threshold(series) and state['coverage']['coverage_open']
                  else 2)
    if not budget.can('windows') or not budget.can('posts', post_slots) \
            or (owed is None and not budget.can('queries')):
        return 'deferred'
    budget.take('windows')
    fresh = owed is None
    window = anomaly_cursor.window_text(end_s, evaluation)
    detail: dict[str, Any] | None = None
    # The turn is taken before the work is done, not after it succeeds. This is the one write whose
    # purpose is fairness rather than durability, and it has to be durable for the same reason the
    # others do: a marker that lives in a loop variable is forgotten by the restart that most needs
    # to remember it, and the refused series at the head of the list would be served again.
    anomaly_cursor.serve(document, series)
    if fresh:
        # Owed before it is read: a window whose verdict was never computed leaves no payload behind,
        # and without this write the only record that the producer ever began it is in a process that
        # can die or fall behind the clock. The anchor warning rides in the same write, so a first
        # attempt costs one fsync and not two.
        anomaly_cursor.owe(document, series, window_end_s=end_s)
        if state['anchored_at'] is None and not state['anchor_logged']:
            # Explicit, once, and no invented number: how many windows were missed is not knowable
            # from what the store still holds, and a count computed from the oldest training point
            # would be a guess wearing a measurement.
            log.warning('Anomaly series anchored at a completed window; every evaluation window '
                        'before it was never judged and is not being replayed',
                        extra={'series': series['id'], 'window_end': window['end'],
                               'replayed_history': False, 'missed_windows': 'unknown'})
            anomaly_cursor.mark_anchored(document, series)
        anomaly_cursor.save(path, document)
        budget.take('queries')
        verdict = _verdict(series, query, end_s=end_s, source=source)
        if document['schema_version'] == anomaly_cursor.COVERAGE_SCHEMA_VERSION:
            after, coverage_status = anomaly_cursor.coverage_transition(
                state['coverage'], verdict.outcome, anomaly_cursor.coverage_threshold(series))
            deliveries = ([_coverage_delivery(series, verdict, coverage_status, source)]
                          if coverage_status else [])
            if verdict.finding is not None:
                deliveries.append((verdict.sample, verdict.finding))
            if deliveries:
                anomaly_cursor.begin_coverage(document, series, window=verdict.window,
                                              outcome=verdict.outcome, deliveries=deliveries,
                                              coverage_after=after)
            else:
                state['coverage'] = after
        else:
            deliveries = None
        if verdict.outcome in anomaly_cursor.SILENT_VERDICTS and not deliveries:
            anomaly_cursor.acknowledge(document, series, window_end_s=end_s, verdict=verdict.outcome)
            anomaly_cursor.save(path, document)
            return _report(series, state, result=verdict.outcome, now=now, evaluation=evaluation,
                           window_end=window['end'], detail=verdict.detail)
        if document['schema_version'] == anomaly_cursor.SCHEMA_VERSION:
            anomaly_cursor.begin(document, series, window=verdict.window, sample=verdict.sample,
                                 event=verdict.finding)
        anomaly_cursor.save(path, document)
        detail = verdict.detail
    else:
        # A replay has no owed-window write for the marker to ride with, so it gets its own — and it
        # still comes before the POST: a cursor that cannot record whose turn this was is a cursor
        # that must not be sending anything.
        anomaly_cursor.save(path, document)
    pending = state['pending']
    _deliver(platform, pending, budget=budget)
    outcome = _pending_outcome(pending)
    anomaly_cursor.acknowledge(document, series, window_end_s=end_s, verdict=outcome)
    anomaly_cursor.save(path, document)
    return _report(series, state, result=outcome, now=now, evaluation=evaluation,
                   window_end=pending['window']['end'], detail=detail,
                   replayed=not fresh)


def _report(series: Mapping[str, Any], state: Mapping[str, Any], *, result: str, now: dt.datetime,
            evaluation: int, window_end: str | None = None, detail: Mapping[str, Any] | None = None,
            replayed: bool = False) -> str:
    """Write the one INFO line this window earned and hand back its word for the round summary.

    One line per series per window, and no line for a window that was not attempted: the counts that
    make a silent worker distinguishable from a busy one come from the round line `main` writes, so a
    healthy round over three caught-up series is four lines and a round walking a week of backlog is
    bounded by the round budget, not by the size of the gap.
    """
    extra: dict[str, Any] = {'series': series['id'], 'result': result,
                             'lag_windows': anomaly_cursor.lag_windows(state, now_s=now.timestamp(),
                                                                      evaluation=evaluation)}
    if window_end is not None:
        extra['window_end'] = window_end
    if replayed:
        extra['replayed'] = True
    if detail:
        extra.update(detail)
    log.info('Anomaly window finished', extra=extra)
    return result


def tick(index_path: Path | str, config: Mapping[str, Any], query: ClickHouse, platform: JsonClient,
         cursor_path: Path | str, *, now: dt.datetime, source: str,
         budget: RoundBudget | None = None) -> dict[str, Any]:
    """Run one bounded round over every configured series and report exactly what it spent.

    One round walks windows **ascending and contiguously per series** and **round-robin across
    series** — the queue starts after the series the cursor last served, one window per series per
    pass, up to :data:`MAX_CATCH_UP_WINDOWS` passes and never more than the round's
    :class:`RoundBudget` allows — so a series with a long backlog cannot spend the round, a series the
    platform keeps refusing cannot spend it either, and every configured series is reached before any
    series is reached twice. The fairness state is the cursor's ``last_served`` marker rather than a
    position in this loop, so the guarantee is the same in the process after a restart and for series
    whose owed windows are *different* hours (which is where counting refusals at equal timestamps
    cannot help: different windows never tie). `pending` retries sit at the front of their own series'
    queue by construction, so nothing newer is judged over an undelivered verdict.

    The document is loaded once and written at the moments that carry consequence (that this series
    has the turn, that a window is being attempted, that its payloads exist, and that it was
    acknowledged); a refusal writes only the refusal counter. The summary is the round's own
    accounting, and every word in it is a count and not a claim about the platform:

    ``result``         `refused` if any window was refused, else `delivered` if any event was
                       acknowledged, else `idle` if any window advanced with nothing to say, else
                       `deferred` when the round could not attempt one single window and a configured
                       series still owes one (a budget of zero is legal, and a round that spent nothing
                       over a standing backlog is behind, not current), else `caught_up`. The order is
                       a precedence and not a menu: once a round attempted something, what it did
                       outranks what it ran out of budget for, and the part it did not reach is the
                       `lag_windows` count reported beside that word, never in place of it.
    ``windows``        window attempts spent, from the budget — pending retries included.
    ``queries``        series reads spent; a replay costs none.
    ``posts``          HTTP attempts spent; two per window with a verdict.
    ``delivered``      windows whose firing event was acknowledged this round.
    ``recovered``      windows whose in-band event (which closes an open incident) was acknowledged.
    ``no_verdict``     windows advanced with nothing posted — `idle`, `insufficient`, `unjudgeable`.
                       Counted apart from `delivered` on purpose: judged is not the same claim as
                       reported, and folding them together would make a quiet series look busy.
    ``refusals``       windows this round could not deliver, per-series counters also in the file.
    ``lag_windows``    completed windows still owed across the configured series, this instant.
    ``pending``        configured series currently holding an undelivered batch.
    ``stale_entries``  cursor entries no configuration names: retained, reported, never deleted.
    ``unresolved_pending``
                       those retained entries that also hold a batch — owed by a series nobody
                       configures any more, which is an operator's to resolve, not this round's.
    ``series``         one row per configured series, in configuration order, each carrying the word
                       that series itself earned — `refused`, `delivered`, `recovered`, `idle`,
                       `insufficient`, `unjudgeable`, `caught_up` (this cursor owes it nothing) or
                       `deferred` (the round had nothing left to spend on it) — beside its lifetime
                       counters, which saturate and so read as a lower bound at the ceiling.

    An undeclared resource, or a configured series whose stored entry no longer matches the resolved
    configuration (its binding, the window positions it holds, or an owed batch that configuration no
    longer authorises), raises out of the whole round before any of it happens: no query, no POST, no
    byte.
    """
    series_list = list(config['series'])
    budget = budget or RoundBudget()
    path = Path(cursor_path)
    document = anomaly_cursor.load(path, source=source, coverage=any(
        anomaly_cursor.coverage_threshold(series) for series in series_list))
    _require_declared(index_path, series_list)
    _require_bindings(series_list, document, source=source, now=now)
    outcomes: dict[str, str] = {}
    turns: dict[str, int] = {}
    settled: set[str] = set()
    steps = {'delivered': 0, 'recovered': 0, 'no_verdict': 0, 'refusals': 0}
    for _pass in range(MAX_CATCH_UP_WINDOWS):
        advanced = 0
        for series, end_s in _owed(series_list, document, now_s=now.timestamp()):
            series_id = series['id']
            if series_id in settled or turns.get(series_id, 0) >= MAX_CATCH_UP_WINDOWS:
                continue
            if end_s is None:
                settled.add(series_id)
                # A series with nothing to do says so once per round; one that has just finished a walk
                # already said what it did, and is not asked to repeat itself. Its row still has to say
                # `caught_up`: a series the cursor has brought all the way up is not a series that was
                # never reached, and the row is what a reader greps for the difference.
                if series_id not in outcomes:
                    outcomes[series_id] = 'caught_up'
                    _report(series, document['series'][series_id], result='caught_up', now=now,
                            evaluation=int(series['evaluation_seconds']))
                continue
            try:
                word = _step(series, query, platform, document, path, end_s=end_s, budget=budget,
                             now=now, source=source)
            except (OSError, ValueError) as exc:
                word = 'refused'
                _refuse(document, series, path, exc)
            turns[series_id] = turns.get(series_id, 0) + 1
            previous = outcomes.get(series_id)
            if previous is None or _LOUDER.get(word, 0) >= _LOUDER.get(previous, 0):
                outcomes[series_id] = word
            if word == 'refused':
                steps['refusals'] += 1
                settled.add(series_id)
            elif word == 'deferred':
                settled.add(series_id)
            elif word in anomaly_cursor.EVENT_VERDICTS:
                steps['delivered' if word == 'delivered' else 'recovered'] += 1
                advanced += 1
            else:
                steps['no_verdict'] += 1
                advanced += 1
        if advanced == 0:
            break
    named = [series['id'] for series in series_list]
    stale = anomaly_cursor.stale_entries(document, named)
    unresolved = anomaly_cursor.unresolved_pending(document, named)
    if stale:
        log.warning('Anomaly cursor holds series entries no configuration names; they are retained '
                    'and nothing here deletes them',
                    extra={'stale_entries': len(stale), 'unresolved_pending': len(unresolved)})
    rows = []
    for series in series_list:
        state = document['series'].get(series['id'])
        evaluation = int(series['evaluation_seconds'])
        # The same question `_owed` asked before the round, asked again after it: what this series
        # still owes, counted from the window it would be given next rather than from the clock.
        following = _next_end(series, state, now.timestamp())
        lag = (0 if following is None else
               1 + max(0, (anomaly_cursor.align_end(now_s=now.timestamp(), evaluation=evaluation)
                           - following) // evaluation))
        # The three counts are the cursor's lifetime counters and they saturate at
        # `anomaly_cursor.MAX_COUNT`: a row reading exactly that ceiling is a lower bound ("at least
        # this many"), not a census of what the series has ever done. See `_bump` for why clamping is
        # the cheaper lie.
        rows.append({'series': series['id'], 'result': outcomes.get(series['id'], 'deferred'),
                     'delivered': 0 if state is None else state['delivered'],
                     'no_verdict': 0 if state is None else state['no_verdict'],
                     'refusals': 0 if state is None else state['refusals'],
                     'lag_windows': lag, 'pending': bool(state and state['pending'])})
    lag_left = sum(row['lag_windows'] for row in rows)
    # A zero or tight budget is legal, and a round that could not attempt a single window over a
    # standing backlog is `deferred`, never `caught_up`: the two are opposite claims about the same
    # file. Once the round did attempt something, the old precedence holds and the lag it could not
    # reach is reported beside the word in `lag_windows` rather than replacing it.
    attempted = budget.used['windows'] > 0
    summary = {'result': ('refused' if steps['refusals'] else
                          'delivered' if steps['delivered'] + steps['recovered'] else
                          'idle' if steps['no_verdict'] else
                          'deferred' if lag_left and not attempted else 'caught_up'),
               'windows': budget.used['windows'], 'queries': budget.used['queries'],
               'posts': budget.used['posts'], 'lag_windows': lag_left,
               'pending': sum(1 for row in rows if row['pending']), 'stale_entries': stale,
               'unresolved_pending': unresolved, 'series': rows, **steps}
    return summary


def _refuse(document: dict[str, Any], series: Mapping[str, Any], path: Path,
            exc: BaseException) -> None:
    """Count a refused window without moving the cursor, and say so once.

    The pending batch, the cursor position and every other counter stay as they were; the only thing
    written is the refusal counter, and if *that* cannot be written — the cursor itself is what failed,
    which is exactly what a binding or corruption refusal is — the previous file is left whole and the
    round carries on with the other series. A refusal never acks anything: the window is still owed at
    the front of this series' queue when the next round loads it.

    "Left whole" is the **before-the-rename** half of ``save``'s two failure stories and nothing more:
    a write that fails *after* ``os.replace`` has the new bytes already installed (see
    :func:`anomaly_cursor.save`), so this path reasons only about the window that stays owed and never
    about which version of the file it ended up holding.
    """
    try:
        anomaly_cursor.note_refusal(document, series)
        anomaly_cursor.save(path, document)
    except (OSError, ValueError):
        pass
    log.warning('Anomaly window refused; the cursor is not advanced and the batch stays pending',
                extra={'series': series['id'], 'error_class': type(exc).__name__})


def main() -> int:
    """Run the producer loop; exit 0 without touching anything when nothing is configured.

    Three start-time facts, in this order, and each one is a visible refusal rather than a fallback:
    the configuration must parse, ``LO_ANOMALY_CURSOR`` must name an absolute path whose private
    parent already exists, and this process must win ``exclusive_owner`` on that cursor for its whole
    life — never inferred from a file's presence, never released early, and never unlinked. Holding
    the lock across the loop is what makes one cursor belong to one writer; a lock held elsewhere
    surfaces here as an :class:`OSError` and exits 1, which is the correct reading of "something else
    is already judging these series".

    A round that fails is logged and retried: the cursor is not advanced, so the same window is owed
    again on the next tick. This worker neither reads nor writes a notification mode — it is a
    producer, and the delivery decision belongs to the platform service like every other source's.
    """
    stack = contextlib.ExitStack()
    try:
        config = producer_config()
        if config is None:
            return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        log.warning('Anomaly producer cannot start; configuration is missing or invalid',
                    extra={'error_class': type(exc).__name__})
        return 1
    try:
        try:
            cursor = anomaly_cursor.cursor_location()
        except anomaly_cursor.CursorRefusal as exc:
            log.warning('Anomaly producer cannot start; the cursor path named is refused',
                        extra={'variable': anomaly_cursor.CURSOR_ENVIRONMENT,
                               'error_class': type(exc).__name__})
            return 1
        if cursor is None:
            # The one refusal an operator is most likely to hit, so it names the variable instead of an
            # error class: a configured producer that cannot remember what it said has no safe way to
            # run, and "off because nothing was named" is not what happened here.
            log.warning('Anomaly producer cannot start; a configured producer will not deliver verdicts '
                        'it cannot re-send',
                        extra={'variable': anomaly_cursor.CURSOR_ENVIRONMENT,
                               'reason': 'no cursor path named'})
            return 1
        anomaly_cursor.private_parent(cursor)
        allow_http = os.environ.get('LO_INTERNAL_ALLOW_HTTP') == '1'
        query = ClickHouse(os.environ['LO_CLICKHOUSE_URL'], os.environ['LO_CLICKHOUSE_USER'],
                           read_credential('LO_CLICKHOUSE_PASSWORD'), allow_http=allow_http)
        platform = JsonClient(os.environ['LO_PLATFORM_URL'], read_credential('LO_PRODUCER_TOKEN'),
                              allow_http=allow_http)
        index_path, source = os.environ['LO_INDEX_PATH'], os.environ[SOURCE_ENVIRONMENT]
        label(source)
        stack.enter_context(exclusive_owner(cursor))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        log.warning('Anomaly producer cannot start; configuration is missing or invalid',
                    extra={'error_class': type(exc).__name__})
        stack.close()
        return 1
    log.info('Anomaly producer started', extra={'series': len(config['series']),
                                                'tick_seconds': config['tick_seconds']})
    try:
        while True:
            try:
                summary = tick(index_path, config, query, platform, cursor,
                               now=dt.datetime.now(dt.timezone.utc), source=source)
                log.info('Anomaly round finished', extra={name: summary[name] for name in ROUND_FIELDS})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                log.warning('Anomaly round unavailable; the cursor is not advanced, this round repeats',
                            extra={'error_class': type(exc).__name__})
                log.debug('Anomaly round failed', exc_info=True)
            time.sleep(config['tick_seconds'])
    finally:
        stack.close()


if __name__ == '__main__':
    raise SystemExit(main())

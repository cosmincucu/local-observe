"""The anomaly producer's durable cursor: which window was judged, what is owed to the platform.

The original single-delivery contract below describes schema 1 (coverage disabled).
Schema 2, created only for a fresh opt-in deployment, stores up to two complete
deliveries per window and commits coverage state with the final acknowledgement.
Existing schema-1 files are never automatically converted. See the unit document.

This file holds *state about deliveries*. No verdict maths, no HTTP, no store: one closed JSON
document, written by the one process that holds ``exclusive_owner`` on it for its whole life, which
answers the five questions the producer cannot otherwise answer after a restart:

* **which evaluation windows of this series have both POSTs accepted** (``last_acked_end``), so a
  restart resumes at the cursor and never at the clock;
* **which window it began and did not finish** (``owed_end``), which is what a *failed read* leaves
  behind: no payload exists for a verdict that was never computed, so without this the entry would
  look untouched and the next round — with a newer clock — would anchor on a later window and skip the
  hour it had already tried;
* **what bytes are still owed** (``pending``) — the exact evidence sample and the exact event this
  producer intended to POST — so a retry resends them without re-reading the series;
* **how much backlog is left** (``lag_windows``) and how many refusals a series has stacked up, so
  "this producer is behind" is a countable number in a log line rather than an impression; and
* **whose turn it was last** (``last_served``), the round-robin position that makes a fair round out
  of durable state instead of loop order — see :func:`rotation`.

The difference between the two debts is the difference between re-reading and not: an owed *attempt* is
re-read (nothing about that window was ever promised to anybody, so a fresh verdict is not a changed
one), while an owed *batch* is replayed byte for byte (recomputing it could yield a different value and
therefore a different event, which the platform refuses as `Event retry changed contents`).

Why the pending batch is stored as payloads rather than as a plan to recompute: the verdict for a
window is a function of what the store happens to hold *now*, and retention moves. Recomputing an old
window after a crash can yield a different value, a different instant, and therefore a different
``sample_id`` and a different event — which the platform refuses as `Event retry changed contents`,
and which would in any case be a second opinion about a window this producer already answered. The
stored payload plus the one serializer every POST here goes through
(``http.JsonClient``: ``canonical(payload).encode()``, imported as :func:`wire_bytes`) is what makes a
retry the *same request*; the two digests stored beside the payloads are that claim re-checked on
every load. A pending batch whose bytes no longer re-serialise to its own digests is corruption, and
is refused rather than repaired.

A pending batch's two digests are **corruption checks, not authentication**. Anyone who can rewrite
this file can rewrite both numbers with it; what the digests buy is the refusal of a truncated,
torn or hand-edited payload, and nothing more. Nothing here signs, seals or verifies the file against
a key, and no claim in this module should be read as if it did.

Bindings, and at which level: ``schema_version`` (the document's own shape), ``source`` (which
producer identity wrote it) and ``last_served`` (whose turn it was) at the top; ``series id``,
``resource_id``, the reviewed ``sql_sha256`` and every knob that can change a verdict, per entry.
Deliberately **not** at the top: a whole-config binding would mean that adding or retitling one series
destroys every other series' backlog and every undelivered batch, which is a worse failure than the
one it would catch — the per-series binding already refuses the cursor for the series that actually
changed.

Scheduling has its own paragraph because it was the correction: the order across series comes from
``last_served``, written *before* the attempt, and not from the owed windows (:func:`rotation`,
:func:`serve`). A permanently refused series owes the same window forever, so any ordering that leads
with time puts that one refusal at the front of every round and every restart. Per-series windows stay
ascending and contiguous; across series, a turn is what is shared. A series the file has never begun is
anchored at **its own newest completed window** — the first-start rule of the durable anomaly cursor, unchanged by what
any sibling owes: there is no shared-horizon, backfill or join-depth policy here, and a new series is
not handed a backlog it was never configured to judge.

Scope, stated plainly because it is a limit and not a detail: this is **one host's local
filesystem**. The document is a plain file behind an advisory lock, so it is correct for one producer
on one machine on a local filesystem, and it is not cluster state. Nothing in this module can tell a
local filesystem from a network one — there is no portable check that distinguishes them reliably —
so an NFS, SMB/CIFS, or mapped-drive deployment is **unsupported and does not necessarily fail
closed**: ``flock`` is host-local or absent on such mounts, and an unsupported mount may raise at
start or may answer the lock happily on both hosts at once. The operator provisions and verifies a
local path; the code refuses only the path *shapes* it can actually see (relative paths, ``..`
symlinked ancestry, and explicit UNC/device forms on Windows), and mapped drive letters or POSIX
remote mounts are outside what it can see.

Durability is equally limited. The payload is written to a temporary file, ``fsync``ed, and renamed
atomically, which is what a *running kernel* needs in order to not show a half-written file; it is
not a proof about power loss, controller write-back caches or any particular filesystem's semantics,
and this implementation has not verified hardware behaviour on any platform. Only POSIX has a
directory ``fsync``, so on Windows the durability of the rename itself is unverified: a crash at that
instant can lose the rename. What losing it costs is one unacknowledged window that is retried —
never a false acknowledgement, because nothing is acked here before both POSTs answered. If the file
is lost (a disk failure, a restore from before it), the remembered history is lost with it: the
producer anchors as if for the first time and says so, and **nothing here can reconstruct what was
owed or promise that no duplicate incident follows**.

Every refusal in this module is read-only. A cursor it refuses is left byte-for-byte as it was found —
never rewritten, truncated, migrated or deleted — because this file is the only record of what the
producer already told the platform, and a monitor that "fixes" its own memory by forgetting turns an
outage into a clean sheet. The operator's remedy is always explicit:
``docs/units/anomaly-cursor.md``.
"""
import datetime as dt
import json
import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from local_observe.inventory.validation import canonical, digest, timestamp, utc_text
from .state import StateError, label, validate_event

# The variable naming this cursor. Stated here, not in anomaly.py, so the requirement ("a configured
# producer with no cursor does not start") lives in the file about the state that can be lost.
CURSOR_ENVIRONMENT = 'LO_ANOMALY_CURSOR'
SCHEMA_VERSION = 1
COVERAGE_SCHEMA_VERSION = 2
COVERAGE_KEYS = frozenset({'previously_judgeable', 'consecutive_unjudgeable', 'coverage_open'})


def coverage_threshold(series: Mapping[str, Any]) -> int:
    value = series.get('coverage_unjudgeable_windows', 0)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise CursorRefusal('coverage_unjudgeable_windows must be an integer in 0..100')
    return value


def coverage_initial() -> dict[str, Any]:
    return {'previously_judgeable': False, 'consecutive_unjudgeable': 0, 'coverage_open': False}


def _validated_coverage(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != COVERAGE_KEYS:
        raise CursorRefusal('Anomaly coverage state holds unknown or missing fields')
    if type(value['previously_judgeable']) is not bool or type(value['coverage_open']) is not bool:
        raise CursorRefusal('Anomaly coverage flags must be booleans')
    count = value['consecutive_unjudgeable']
    if type(count) is not int or not 0 <= count <= 100:
        raise CursorRefusal('Anomaly coverage count must be an integer in 0..100')
    if not value['previously_judgeable'] and (count or value['coverage_open']):
        raise CursorRefusal('Anomaly coverage cannot precede a judgeable window')
    return dict(value)


def coverage_transition(previous: Mapping[str, Any], outcome: str,
                        threshold: int) -> tuple[dict[str, Any], str | None]:
    """Pure next state and optional coverage status, committed only with the window ack."""
    next_state = _validated_coverage(previous)
    if not isinstance(outcome, str) or outcome not in EVENT_VERDICTS | SILENT_VERDICTS:
        raise CursorRefusal('Unknown coverage verdict')
    if not threshold:
        return coverage_initial(), None
    status = None
    if outcome in EVENT_VERDICTS:
        next_state['previously_judgeable'] = True
        next_state['consecutive_unjudgeable'] = 0
        if next_state['coverage_open']:
            status = 'resolved'
            next_state['coverage_open'] = False
    elif outcome == 'unjudgeable' and next_state['previously_judgeable']:
        next_state['consecutive_unjudgeable'] = min(100, next_state['consecutive_unjudgeable'] + 1)
        if next_state['consecutive_unjudgeable'] >= threshold and not next_state['coverage_open']:
            status = 'firing'
            next_state['coverage_open'] = True
    else:
        next_state['consecutive_unjudgeable'] = 0
    return next_state, status


def coverage_version(series: Mapping[str, Any]) -> str:
    return digest(['anomaly-coverage', series_binding(series)])[:16]
# What one document may hold. The real ceiling on a pending batch is the platform's own:
# `state.validate_event` refuses an event over 64 KiB and `state.put_evidence` refuses a sample over
# 2 KiB, so a cursor full of pending batches could reach ~2.2 MiB of *possible* payload while a real
# anomaly event measures about 600 bytes. MAX_CURSOR_BYTES is therefore not a size an operator is
# expected to reach by configuring series; it is the line past which the file is damage.
MAX_EVENT_BYTES = 65_536
MAX_SAMPLE_BYTES = 2_048
MAX_CURSOR_BYTES = 2_097_152
# Configured series are capped at anomaly.MAX_SERIES (16); the rest of this bound is the room a
# series needs to be *retained* after it leaves the configuration. Past it the file holds more
# history than this producer could have written, and the refusal says so rather than dropping
# entries to fit — the entries it would drop are windows the platform has never accepted.
MAX_ENTRIES = 32
MAX_COUNT = 1_000_000_000_000
# ``last_served`` is the round-robin position: which configured series this cursor gave its last
# window attempt to. It is one string rather than a counter on purpose — a counter that saturates
# eventually ranks everything equally and quietly hands the queue back to oldest-window-first, which
# is the starvation this marker exists to prevent.
CURSOR_KEYS = frozenset({'schema_version', 'source', 'last_served', 'series'})
SERIES_STATE_KEYS = frozenset({'binding', 'last_acked_end', 'anchored_at', 'anchor_logged',
                               'owed_end', 'delivered', 'no_verdict', 'refusals', 'pending'})
PENDING_KEYS = frozenset({'window', 'sample', 'event', 'evidence_sha256', 'event_sha256'})
WINDOW_KEYS = frozenset({'start', 'end'})
# The subset of a canonical event this cursor depends on for a stable retry. The whole shape is
# `state.validate_event`'s contract and stays there: restating thirteen fields here would be a second
# vocabulary that has to move every time the platform's moves.
EVENT_REQUIRED = frozenset({'source', 'source_event_id', 'kind', 'status', 'window', 'rule_id',
                            'evidence'})
SAMPLE_REQUIRED = frozenset({'sample_id', 'observed_at', 'ok', 'value'})
# Verdicts that put an event on the wire, and verdicts that advance a window with nothing delivered.
# Counting the two together would make "judged forty windows" read as "reported forty incidents".
EVENT_VERDICTS = frozenset({'delivered', 'recovered'})
SILENT_VERDICTS = frozenset({'idle', 'insufficient', 'unjudgeable'})
# The evidence query kind and the two parameter names an anomaly verdict is allowed to carry. Spelled
# once here so the replay preflight can name them; both are the platform's vocabulary
# (``state.validate_event``'s approved list), restated as a check and never widened.
REPLAY_QUERY_TYPE = 'metric-threshold'
REPLAY_PARAMETERS = frozenset({'rule_id', 'sample_id'})
SHA256_TEXT = re.compile(r'[0-9a-f]{64}')
PRIVATE_PARENT_UMASK = 0o077


class CursorRefusal(ValueError):
    """The cursor document is not one this producer may trust. Its bytes are left as they were."""


def cursor_location(environment: Mapping[str, str] | None = None) -> Path | None:
    """Return the configured cursor path, refusing a location that is not one host's private file.

    Unset or blank answers None — the difference between "off" and "misconfigured" — and
    `anomaly.main` turns that None into a refusal once a configuration *is* named. A relative path is
    refused rather than defaulted: it is state that moves when the service manager's working
    directory moves, and a producer that silently opens a *different* cursor is worse than one that
    refuses to start. Absolute means drive-anchored on Windows and root-anchored on POSIX, which is
    why the same value cannot be shared between the two.
    """
    environ = os.environ if environment is None else environment
    raw = (environ.get(CURSOR_ENVIRONMENT) or '').strip()
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute() or '..' in candidate.parent.parts or '..' in candidate.parts:
        raise CursorRefusal(f'{CURSOR_ENVIRONMENT} must name an absolute host-local path with no '
                            '".." segments')
    if os.name == 'nt' and raw.replace('/', '\\').startswith('\\\\'):
        raise CursorRefusal(f'{CURSOR_ENVIRONMENT} names a UNC or device path; the cursor is '
                            'host-local state and its parent must be a private local directory. '
                            'A mapped drive letter that points at a share cannot be detected here '
                            'and must not be used')
    return candidate


def symlink_present(candidate: Path) -> bool:
    """Return whether *candidate* is itself a symbolic link, as this module asks the filesystem.

    One function because it is the only place the cursor consults the link status of a path, and the
    one place a test can substitute for a host that will not create links: the deterministic refusal
    tests patch *this* predicate and run on every platform, while the real-link cases stay integration
    tests where the OS allows them (``docs/testing-standards.md``). What it reports is a symbolic
    link: an NTFS junction, another reparse point, a bind mount or a redirected drive letter are not
    reported, which is why directory ancestry is a trusted-provisioning boundary and not a check.
    """
    return candidate.is_symlink()


def _refuse_symlinked_ancestry(path: Path) -> None:
    """Refuse a cursor whose path is reachable through a symlink anywhere above it.

    Checking only the immediate parent would leave the claim larger than the code: a state directory
    reached through ``D:\\logs -> E:\\public`` is the same traversal with one more step under it, and
    the file inherits the reachability of the whole chain, not of the last link in it. Every existing
    ancestor is therefore checked, outermost first, so the refusal names the furthest one up. This
    runs before the file is opened for reading as well as before it is written: a symlink can be put
    in place between two rounds, and a cursor read through one has already leaked its contents.

    Two limits are stated rather than papered over. On Windows ``is_symlink`` reports a symbolic
    link and not an NTFS junction or a reparse point of another kind, and it reports nothing about a
    drive letter that is itself a network redirect; on POSIX it does not see a bind mount. Directory
    ancestry is therefore a **trusted-provisioning** boundary — the operator creates the private
    directory and owns its whole path — and an ancestry an attacker may rewrite is out of scope for
    what this function can see. And this is a **check-then-use** path: it states an assumption rather
    than a guarantee, because nothing here holds the directories it inspected still in place by the
    time the open happens, so a swap in that window is a TOCTOU gap the advisory lock beside the
    cursor does not close. Stronger protection (an opened-directory-handle walk, a platform
    link-resolution syscall with the handle pinned) is out of scope for this implementation, not
    impossible in principle — it is simply not what this code does, and the docs say so.
    """
    for ancestor in reversed(path.parents):
        if symlink_present(ancestor):
            raise CursorRefusal(f'Anomaly cursor path is reachable through a symlinked directory '
                                f'({ancestor}); the cursor is not opened or written through a link')


def private_parent(path: Path | str) -> Path:
    """Return the cursor's parent directory, refusing one nobody told this producer about.

    The parent must already exist, and neither it nor any directory above it may be a symlink. This
    file is written 0600 and holds the payloads of verdicts, so a producer that created its own
    directory would be choosing the permissions around its own state — and would happily create it
    inside a mount somebody else exported. On POSIX the parent must carry no group or other access
    bit at all; on Windows there is no mode to check and no ACL proof is claimed here, so the parent
    is checked for existing and for not being a link, and its protection is the operator's.
    """
    destination = Path(path)
    parent = destination.parent
    _refuse_symlinked_ancestry(destination)
    if symlink_present(parent):
        raise CursorRefusal('Anomaly cursor parent is a symlink')
    if not parent.is_dir():
        raise CursorRefusal('Anomaly cursor parent directory does not exist; create it privately '
                            '(mode 0700) before starting the producer')
    if os.name != 'nt' and parent.stat().st_mode & 0o777 & PRIVATE_PARENT_UMASK:
        raise CursorRefusal('Anomaly cursor parent is reachable by group or other; it must be mode '
                            '0700')
    return parent


def wire_bytes(payload: Any) -> bytes:
    """Return the exact bytes ``http.JsonClient.request`` puts on the wire for *payload*."""
    return canonical(payload).encode()


def payload_digest(payload: Any) -> str:
    """Return the sha256 of :func:`wire_bytes` for *payload*: the identity of that request body."""
    return digest(payload)


def series_binding(series: Mapping[str, Any]) -> str:
    """Return the digest of everything a stored verdict is a statement about, for one series.

    Identity (`id`, `resource_id`), the reviewed SQL text's digest, and every knob that changes a
    verdict's numbers or the event carrying it (`season`, `k`, `window_days`, `min_points`,
    `min_per_bucket`, `evaluation_seconds`). `tick_seconds` is absent on purpose: it is how often the
    producer looks, not what a window means, and retuning it must not discard a backlog. The window
    itself is absent too — it lives inside the stored payload.
    """
    for field in ('id', 'resource_id'):
        if field not in series:
            raise CursorRefusal('Anomaly cursor binding needs a series id and a resource id')
        _label(series[field], 'series id' if field == 'id' else 'resource id')
    values = ['anomaly-series', series['id'], series['resource_id'], series['sql_sha256'],
                   series['season'], float(series['k']), float(series['window_days']),
                   float(series['min_points']), float(series['min_per_bucket']),
                   float(series['evaluation_seconds'])]
    threshold = coverage_threshold(series)
    if threshold:
        values.extend(['coverage_unjudgeable_windows', threshold])
    return digest(values)


def empty_document(source: str, *, coverage: bool = False) -> dict[str, Any]:
    """Return the document a first start begins from: nothing judged, nothing owed, nobody served."""
    return {'schema_version': COVERAGE_SCHEMA_VERSION if coverage else SCHEMA_VERSION,
            'source': _label(source, 'producer identity'),
            'last_served': None, 'series': {}}


def load(path: Path | str, *, source: str, coverage: bool = False) -> dict[str, Any]:
    """Return the validated cursor for producer identity *source*, or a fresh document if none yet.

    Every refusal is a `CursorRefusal` raised before a single byte is written: unreadable or
    duplicated-key JSON, an over-cap file, unknown or missing keys, a foreign ``schema_version``, a
    document written for another producer identity, a round-robin marker that is not an identifier, an
    entry with an impossible shape, counter or internal ordering, a pending batch whose payloads
    disagree with the digests beside it, and a symlink as the cursor or anywhere in the directories
    above it. Refusal means *read nothing and write nothing*: the file is left as it was found.

    What this does **not** do is authenticate the file. The digests are recomputed from the payloads
    and compared to the numbers stored next to them, which catches a torn or hand-edited batch; it
    does not catch a writer who rewrote both, and no claim here says it does (see the module docstring
    and ``docs/units/anomaly-cursor.md``).
    """
    candidate = Path(path)
    if symlink_present(candidate):
        raise CursorRefusal('Refusing a symlinked anomaly cursor')
    _refuse_symlinked_ancestry(candidate)
    if not candidate.exists():
        return empty_document(source, coverage=coverage)
    with candidate.open('rb') as stream:
        raw = stream.read(MAX_CURSOR_BYTES + 1)
    if len(raw) > MAX_CURSOR_BYTES:
        raise CursorRefusal(f'Anomaly cursor exceeds {MAX_CURSOR_BYTES} bytes')
    try:
        document = json.loads(raw, object_pairs_hook=_no_duplicates)
    except CursorRefusal:
        raise
    except (ValueError, UnicodeDecodeError):
        raise CursorRefusal('Anomaly cursor is not JSON') from None
    if not isinstance(document, dict) or set(document) != CURSOR_KEYS:
        raise CursorRefusal('Anomaly cursor holds unknown or missing top-level keys')
    _schema_version(document['schema_version'])
    if coverage and document['schema_version'] == SCHEMA_VERSION:
        raise CursorRefusal('Coverage requires an explicit reviewed cursor migration; retain the '
                            'existing cursor and disabled configuration. No automatic migration.')
    if document['source'] != _label(source, 'producer identity'):
        raise CursorRefusal('Anomaly cursor was written by a different producer identity, so this '
                            f'{CURSOR_ENVIRONMENT} points at another producer\'s state')
    _served_marker(document['last_served'])
    _validated_series(document, source=document['source'])
    return document


def save(path: Path | str, document: Mapping[str, Any]) -> None:
    """Write the cursor atomically and privately, refusing what it would refuse to read back.

    The document is validated *before* the first byte is written, so this function can never be how a
    producer creates a cursor it would then refuse to open. The write sequence is the one
    ``inventory.index.build`` uses, for the same reasons: a name from ``mkstemp`` (never a
    stem-derived ``.tmp`` that two writers sharing a stem would overwrite), the whole payload,
    ``flush``, ``fsync``, then one atomic ``os.replace``, then a directory ``fsync`` where the platform
    has one. The temporary file is unlinked in ``finally`` — **only our own temporary file**. The
    ``.owner.lock`` beside it is never deleted by anything here: a lock file's presence says nothing
    about a live owner, and removing it is exactly how two processes end up both writing.

    What each failure costs is not the same on both sides of the rename, and the difference is worth
    reading twice. A failure **before** ``os.replace`` — the write, the ``fsync``, the ``chmod``, the
    rename itself — leaves the previous cursor's bytes installed and readable, which is the property
    the producer relies on: the round that could not persist refuses, nothing was POSTed, and the
    owed window is still owed. A failure **after** ``os.replace`` can only come from the POSIX
    directory ``fsync``, and by then the *new* bytes are already installed: they are the file any
    process that keeps running will read, and what is uncertain is whether they survive a power loss
    or a crash of the machine — this code cannot know, and does not claim either way. So a failed
    ``save`` means "the cursor may be the old one or the new one, and its durability is unknown", not
    "the old one is safely still there".

    The producer's response to that uncertainty is the fail-closed half of the design, and it is a
    rule about ordering rather than a promise about files: **a window is never POSTed on the strength
    of a save that did not succeed**, so the next required write happens before the next delivery and
    nothing is delivered until a save has come back clean. A monitor that "fixed" its own memory by
    continuing after a failed write would be reporting verdicts it cannot re-send.
    """
    destination = Path(path)
    if symlink_present(destination):
        raise CursorRefusal('Refusing to write through a symlinked anomaly cursor')
    if destination.is_dir():
        raise CursorRefusal('Anomaly cursor path is a directory')
    private_parent(destination)
    validated = _validated_document(document)
    payload = canonical(validated).encode()
    if len(payload) > MAX_CURSOR_BYTES:
        raise CursorRefusal(f'Anomaly cursor would exceed {MAX_CURSOR_BYTES} bytes; this round '
                            'refuses rather than dropping entries to fit')
    descriptor, temporary = tempfile.mkstemp(dir=str(destination.parent),
                                             prefix='.' + destination.name + '.', suffix='.tmp')
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        if os.name != 'nt':
            handle = os.open(str(destination.parent), os.O_RDONLY)
            try:
                os.fsync(handle)
            finally:
                os.close(handle)
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass


def ensure_entry(document: dict[str, Any], series: Mapping[str, Any]) -> dict[str, Any]:
    """Return the state held for *series*, adding a fresh un-anchored entry when the file has none.

    Adding is the only way an entry appears, and it is bounded: past :data:`MAX_ENTRIES` the producer
    stops rather than evicting, because the entries available to evict are the ones holding windows
    the platform has never accepted.
    """
    series_id = _label(series['id'], 'series id')
    entries = document['series']
    if series_id not in entries:
        if not len(entries) + 1 <= MAX_ENTRIES:
            raise CursorRefusal(f'Anomaly cursor already holds {MAX_ENTRIES} series entries; series '
                                'that left the configuration are retained on purpose, and removing '
                                'their entries is an operator action (docs/units/anomaly-cursor.md)')
        entries[series_id] = {'binding': series_binding(series), 'last_acked_end': None,
                              'anchored_at': None, 'anchor_logged': False, 'owed_end': None,
                              'delivered': 0, 'no_verdict': 0, 'refusals': 0, 'pending': None}
        if document['schema_version'] == COVERAGE_SCHEMA_VERSION:
            entries[series_id]['coverage'] = coverage_initial()
    elif entries[series_id]['binding'] != series_binding(series):
        raise CursorRefusal(f'Anomaly series {series_id} changed underneath the cursor: its stored '
                            'verdicts belong to different configuration, so this round refuses '
                            'rather than mixing the two')
    return entries[series_id]


def serve(document: dict[str, Any], series: Mapping[str, Any]) -> str:
    """Record that one series is being given **this turn**, before anything is read or posted.

    This is the round-robin position, and the whole point of it being written here rather than kept in
    a loop variable is the restart: a producer that remembers "whose turn it was" only in memory gives
    the front of the queue back to whichever series its list happens to reach first, which is exactly
    how a permanently refused series starves the ones behind it. Written and fsynced **before** the
    store is asked anything and before any POST, so a round that dies mid-window leaves the turn
    consumed, and the process after this one continues the rotation instead of restarting it.

    It costs nothing in the case that matters most: for a fresh window the marker rides in the same
    write as :func:`owe`, so a first attempt is still one fsync.
    """
    series_id = _label(series['id'], 'series id')
    ensure_entry(document, series)
    document['last_served'] = series_id
    return series_id


def rotation(document: Mapping[str, Any], names: Iterable[str]) -> list[str]:
    """Return *names* in durable round-robin order: the turn after the last one served, then a wrap.

    The order is a function of the document, not of the caller's loop, so the same cursor answers the
    same question in the next process. A marker naming a series that is not in *names* (it left the
    configuration, or its entry was removed by an operator) starts the rotation at the head of the
    list rather than refusing: the position is a fairness aid, not an identity claim, and the series
    that are configured are the only ones a round can serve.

    Nothing here sorts by *time*. That is deliberate: the oldest owed window is what a permanently
    refused series keeps owing, so an ordering that leads with it puts the same refusal at the front
    of every round forever and starves every series behind it. Per-series windows stay ascending and
    contiguous (:func:`next_window_end` answers that alone); across series, a turn is what is shared.
    """
    listed = list(names)
    last = document['last_served']
    if last in listed:
        cut = listed.index(last) + 1
        return listed[cut:] + listed[:cut]
    return listed


def owe(document: dict[str, Any], series: Mapping[str, Any], *, window_end_s: int) -> dict[str, Any]:
    """Record that one window is **being attempted**, before the store is asked anything about it.

    This is the write that makes a *failed read* cost nothing. A refused POST leaves a pending batch,
    and a pending batch is self-describing: it names its own window. A window whose verdict was never
    computed leaves no payload at all — and without this marker, a first-ever window that died in a
    query would be indistinguishable from a series never judged, so the next round (with a newer clock)
    would anchor on the newest completed window and the failed hour would be skipped with no trace.
    The rule that closes it is the same one the payloads follow: **a window the producer began is owed
    until it is acknowledged**, and the record of beginning it is durable before the read starts.

    A replay of an owed window re-reads the store, which is correct here and only here: nothing about
    this window has ever been promised to the platform, so there is no verdict to keep identical.
    """
    state = ensure_entry(document, series)
    end = _instant_of(window_end_s)
    if state['pending'] is not None and timestamp(state['pending']['window']['end']) != end:
        raise CursorRefusal('Anomaly cursor holds a pending batch for a window other than the one '
                            'being attempted')
    if state['owed_end'] is not None and timestamp(state['owed_end']) != end:
        raise CursorRefusal('Anomaly cursor already owes a different window than the one being '
                            'attempted; catch-up does not skip a window it began')
    if state['last_acked_end'] is not None and end <= timestamp(state['last_acked_end']):
        raise CursorRefusal('Anomaly cursor cannot owe a window it has already acknowledged')
    state['owed_end'] = utc_text(end)
    return state


def begin(document: dict[str, Any], series: Mapping[str, Any], *, window: Mapping[str, str],
          sample: Any, event: Any) -> dict[str, Any]:
    """Record the exact payloads owed for one window, before any POST is attempted.

    One pending batch per series, which is all one window can ever make: one evidence sample and one
    event, both required. The digests are of the bytes the client will send, so a later reader can
    prove the payload it is replaying is the payload that was promised. The window also stays the owed
    one (`owed_end`), so a batch that was never even POSTed cannot become the series' forgotten past.
    """
    state = ensure_entry(document, series)
    if state['pending'] is not None:
        raise CursorRefusal('Anomaly cursor already holds an undelivered window for this series')
    if not isinstance(window, Mapping) or set(window) != WINDOW_KEYS:
        raise CursorRefusal('Anomaly pending window must carry exactly a start and an end')
    if state['owed_end'] is not None and state['owed_end'] != window['end']:
        raise CursorRefusal('Anomaly cursor cannot hold a verdict for a window other than the one it '
                            'began')
    if sample is None:
        raise CursorRefusal('Anomaly cursor cannot hold an event with no evidence sample; every '
                            'anomaly verdict posts both bodies or nothing')
    pending: dict[str, Any] = {'window': {'start': window['start'], 'end': window['end']},
                               'sample': sample, 'event': event,
                               'evidence_sha256': payload_digest(sample),
                               'event_sha256': payload_digest(event)}
    state['pending'] = _validated_pending(pending, document['source'])
    # A batch always implies its window is owed, whoever recorded the attempt: `next_window_end` reads
    # the pending payload first, so this is coherence rather than behaviour.
    state['owed_end'] = window['end']
    return state['pending']


def begin_coverage(document, series, *, window, outcome, deliveries, coverage_after):
    """Persist at most two complete deliveries and the state to commit with their acknowledgement."""
    if document['schema_version'] != COVERAGE_SCHEMA_VERSION:
        raise CursorRefusal('Coverage batches require cursor schema 2')
    state = ensure_entry(document, series)
    if state['pending'] is not None or state['owed_end'] != window['end']:
        raise CursorRefusal('Coverage batch does not match the owed fresh window')
    pairs = [{'window': dict(window), 'sample': sample, 'event': finding,
              'evidence_sha256': payload_digest(sample), 'event_sha256': payload_digest(finding)}
             for sample, finding in deliveries]
    pending = {'window': dict(window), 'outcome': outcome, 'deliveries': pairs,
               'coverage_after': coverage_after}
    state['pending'] = _validated_coverage_pending(pending, document['source'])
    return state['pending']


def _validated_coverage_pending(pending, source):
    if not isinstance(pending, Mapping) or set(pending) != COVERAGE_PENDING_KEYS:
        raise CursorRefusal('Coverage pending batch holds unknown or missing fields')
    deliveries = pending['deliveries']
    if not isinstance(deliveries, list) or not 1 <= len(deliveries) <= 2:
        raise CursorRefusal('Coverage batch must hold one or two deliveries')
    outcome = pending['outcome']
    if not isinstance(outcome, str) or outcome not in EVENT_VERDICTS | SILENT_VERDICTS:
        raise CursorRefusal('Coverage batch has an invalid original verdict')
    pairs = [_validated_pending(item, source, coverage=True) for item in deliveries]
    if any(item['window'] != pending['window'] for item in pairs):
        raise CursorRefusal('Coverage deliveries must share their pending window')
    return {'window': dict(pairs[0]['window']), 'outcome': outcome, 'deliveries': pairs,
            'coverage_after': _validated_coverage(pending['coverage_after'])}


def acknowledge(document: dict[str, Any], series: Mapping[str, Any], *, window_end_s: int,
                verdict: str) -> dict[str, Any]:
    """Mark one window answered, in the only direction a cursor may travel: forward.

    A pending batch may only be cleared by the window it names (acking a *newer* window while an older
    one is owed would silently drop a delivery), the window owed by an attempt (`owed_end`, recorded
    before the store was read) may only be cleared by that same window, no window is ever acked at or
    behind the last one already acked — catch-up is ascending and contiguous — and an event verdict must
    have had a batch to deliver. The anchor is stamped here when the entry has never had one: the first
    window this series ever judged *is* its anchor, and everything before it stays unjudged history.
    """
    state = ensure_entry(document, series)
    end = _instant_of(window_end_s)
    previous = state['last_acked_end']
    if previous is not None and end <= timestamp(previous):
        raise CursorRefusal('Anomaly cursor refuses to acknowledge a window it has already answered')
    if state['pending'] is not None and timestamp(state['pending']['window']['end']) != end:
        raise CursorRefusal('Anomaly cursor holds a pending batch for a different window than the one '
                            'being acknowledged')
    if state['owed_end'] is not None and timestamp(state['owed_end']) != end:
        raise CursorRefusal('Anomaly cursor owes a different window than the one being acknowledged; '
                            'a window it began is not skipped by acknowledging a newer one')
    if verdict not in EVENT_VERDICTS | SILENT_VERDICTS:
        raise CursorRefusal('Anomaly cursor holds an unknown verdict')
    if (verdict in EVENT_VERDICTS) != (state['pending'] is not None):
        raise CursorRefusal('An anomaly event can only be acknowledged with the batch it delivered')
    if state['anchored_at'] is None:
        state['anchored_at'] = utc_text(end)
    state['last_acked_end'] = utc_text(end)
    if state['pending'] is not None and 'deliveries' in state['pending']:
        state['coverage'] = dict(state['pending']['coverage_after'])
    state['pending'] = None
    state['owed_end'] = None
    if verdict in EVENT_VERDICTS:
        _bump(state, 'delivered')
    else:
        _bump(state, 'no_verdict')
    return state


def note_refusal(document: dict[str, Any], series: Mapping[str, Any]) -> dict[str, Any]:
    """Count a refused window. The pending batch and the cursor position stay exactly as they were."""
    state = ensure_entry(document, series)
    _bump(state, 'refusals')
    return state


def mark_anchored(document: dict[str, Any], series: Mapping[str, Any]) -> dict[str, Any]:
    """Record that the "history before this window was not judged" line has been written for it."""
    state = ensure_entry(document, series)
    state['anchor_logged'] = True
    return state


def align_end(now_s: float, evaluation: int) -> int:
    """Return the newest *completed* window end at or before *now_s*: the first-start anchor."""
    _check_evaluation(evaluation)
    if isinstance(now_s, bool) or not isinstance(now_s, (int, float)):
        raise CursorRefusal('Anomaly clock readings must be numbers')
    return int(now_s) // evaluation * evaluation


def next_window_end(state: Mapping[str, Any], *, now_s: float, evaluation: int) -> int | None:
    """Return the next window this series owes, oldest first for that series, or None if caught up.

    Four cases, in this order: a pending batch always comes next (an undelivered window is retried
    before anything newer is judged), then a window whose *attempt* was recorded and never
    acknowledged (:func:`owe` — the failure that leaves no payload behind), then the window after the
    last acknowledged one, then — only for an entry that has never judged anything — the newest
    completed window. That fourth case is the durable anomaly cursor's first-start rule, and it is deliberately asked
    per entry with the clock in hand: which window a *new* series begins at does not depend on what its
    siblings owe, and nothing in this module computes a shared "where the producer stands" for a new
    series to inherit.

    **There is no ``max(last_end + interval, now)`` anywhere in this function**: the resume point is
    the cursor and never the clock, which is the whole difference between *resumed* and *threw the gap
    away*.
    """
    pending = state['pending']
    if pending is not None:
        return int(timestamp(pending['window']['end']).timestamp())
    owed = state.get('owed_end')
    if owed is not None:
        return int(timestamp(owed).timestamp())
    completed = align_end(now_s=now_s, evaluation=evaluation)
    previous = state['last_acked_end']
    if previous is None:
        return completed
    candidate = int(timestamp(previous).timestamp()) + evaluation
    return candidate if candidate <= completed else None


def lag_windows(state: Mapping[str, Any], *, now_s: float, evaluation: int) -> int:
    """Return how many completed windows still have to be judged, the pending batch included."""
    following = next_window_end(state, now_s=now_s, evaluation=evaluation)
    if following is None:
        return 0
    return 1 + max(0, (align_end(now_s=now_s, evaluation=evaluation) - following) // evaluation)


def stale_entries(document: Mapping[str, Any], configured: Iterable[str]) -> list[str]:
    """Return the cursor's series ids that no configuration names, in the order the file holds them.

    Retained, never repaired: a series that left the configuration may still hold a batch the platform
    has not accepted, and deleting it would be the producer acking a delivery it never made.
    """
    named = set(configured)
    return [series_id for series_id in document['series'] if series_id not in named]


def unresolved_pending(document: Mapping[str, Any], configured: Iterable[str]) -> list[str]:
    """Return the retained entries that still hold an undelivered batch: owed, and now unservable."""
    named = set(configured)
    return [series_id for series_id, state in document['series'].items()
            if series_id not in named and state['pending'] is not None]


COVERAGE_PENDING_KEYS = frozenset({'window', 'outcome', 'deliveries', 'coverage_after'})


def migrate_document(document: Mapping[str, Any], *, legacy: list[Mapping[str, Any]],
                     target: list[Mapping[str, Any]], rule_versions: Mapping[str, str],
                     source: str, now: dt.datetime) -> dict[str, Any]:
    """Validate and wrap a schema-1 cursor for explicit offline migration.

    The caller supplies resolved old and target configurations; only the coverage threshold may
    change. Stored series missing from either configuration refuse. Replay validation runs on both
    sides, preserving ordinary payloads, digests, checkpoints and counters. Coverage starts empty;
    a pending ordinary acknowledgement records its normal coverage transition only after delivery.
    Return a new validated schema-2 document without mutating the input or performing any I/O.
    """
    if _schema_version(document['schema_version']) != SCHEMA_VERSION:
        raise CursorRefusal('Anomaly cursor migration expects a schema-1 document')
    identity = _label(document['source'], 'producer identity')
    if identity != _label(source, 'producer identity'):
        raise CursorRefusal('Anomaly cursor migration was asked for a different producer identity '
                            'than the document names')
    legacy_by_id = _migration_series(legacy)
    target_by_id = _migration_series(target)
    if not any(coverage_threshold(series) for series in target_by_id.values()):
        raise CursorRefusal('Anomaly cursor migration needs a target configuration with at least one '
                            'coverage-enabled series; nothing would change without one')
    entries = _validated_series(document, source=identity)
    for name, entry in entries.items():
        # Every schema-2 entry carries coverage, so every stored entry gets one — and every one of them
        # starts at the empty history: this migration remembers no window it never acknowledged.
        entry['coverage'] = coverage_initial()
        configured, written = target_by_id.get(name), legacy_by_id.get(name)
        if configured is None:
            raise CursorRefusal(f'Anomaly cursor holds series {name}, which the target configuration '
                                'does not name. A retained entry keeps its undelivered batch with '
                                'nobody left to replay it; remove that entry as an operator action '
                                '(docs/units/anomaly-cursor.md) before migrating')
        if written is None:
            raise CursorRefusal(f'Anomaly cursor holds series {name}, which is not in the '
                                'configuration the cursor was loaded with (coverage off), so its '
                                'stored verdicts cannot be replay-checked before they are re-bound')
        version = _migration_version(rule_versions, name)
        if entry['binding'] != series_binding(written):
            raise CursorRefusal(f'Anomaly series {name} holds a binding the configuration named here '
                                'does not produce with coverage off, so its stored verdicts belong to '
                                'neither those knobs nor the enabled ones')
        replay_coherent(written, entry, source=identity, now=now, rule_version=version)
        if entry['pending'] is not None:
            outcome = _pending_outcome(entry['pending'])
            next_state, _status = coverage_transition(coverage_initial(), outcome,
                                                      coverage_threshold(configured))
            entry['pending'] = _migration_pending(entry['pending'], source=identity, outcome=outcome,
                                                  coverage_after=next_state)
        entry['binding'] = series_binding(configured)
        replay_coherent(configured, entry, source=identity, now=now, rule_version=version)
    return _validated_document({'schema_version': COVERAGE_SCHEMA_VERSION, 'source': identity,
                                'last_served': document['last_served'], 'series': entries})


def _migration_series(series_list: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Return *series_list* keyed by id, refusing a list that cannot describe a cursor entry."""
    if not isinstance(series_list, list) or not series_list:
        raise CursorRefusal('Anomaly cursor migration needs the old and the new resolved series')
    by_id: dict[str, Any] = {}
    for series in series_list:
        if not isinstance(series, Mapping):
            raise CursorRefusal('Anomaly cursor migration series entry is not a configuration object')
        name = _label(series['id'], 'series id')
        if name in by_id:
            raise CursorRefusal(f'Anomaly cursor migration names series {name} twice')
        coverage_threshold(series)
        by_id[name] = series
    return by_id


def _migration_version(rule_versions: Mapping[str, str], series_id: str) -> str:
    """Return the event-side ``rule_version`` one series' stored verdicts carry.

    The cursor deliberately does not know that digest's ingredient list — it is the producer's, and
    restating it here would be a second vocabulary about what a verdict means (see
    :func:`series_binding`'s docstring for why the two lists differ). So migration is *given* it, and
    given it once per series: one version for both sides is what says "the only thing the target
    configuration changed is the coverage threshold". A knob that also moved would make the stored
    batch belong to neither side, and is refused as the binding drift it is.
    """
    if not isinstance(rule_versions, Mapping) or rule_versions.get(series_id) is None:
        raise CursorRefusal(f'Anomaly cursor migration was given no rule_version for series '
                            f'{series_id}, so its stored verdicts cannot be replay-checked')
    return _label(rule_versions[series_id], 'rule version')


def _pending_outcome(pending: Mapping[str, Any]) -> str:
    """Return the verdict word one stored batch earns; schema 1 asked its event, schema 2 its own."""
    if 'deliveries' in pending:
        return pending['outcome']
    return 'delivered' if pending['event']['status'] == 'firing' else 'recovered'


def _migration_pending(pending: Any, *, source: str, outcome: str,
                       coverage_after: Mapping[str, Any]) -> Any:
    """Re-express one schema-1 batch as a schema-2 envelope, or hand back None untouched.

    The delivery *is* the validated schema-1 batch: same window text, same sample, same event, same two
    digests. Nothing is re-derived, which is what makes the next round's POST the same request.
    """
    if pending is None:
        return None
    return _validated_coverage_pending(
        {'window': dict(pending['window']), 'outcome': outcome, 'deliveries': [pending],
         'coverage_after': dict(coverage_after)}, source)


def replay_coherent(series: Mapping[str, Any], entry: Mapping[str, Any], *, source: str,
                    now: dt.datetime, rule_version: str, coverage_event: bool = False) -> None:
    """Refuse a stored verdict that this configuration no longer authorises, before anything is spent.

    ``load`` can prove the file agrees with **itself**; only the resolved configuration says whether an
    entry's owed batch still belongs to the series it is stored under. A replay POSTs stored bytes, so
    the alternative is finding the mismatch out of band — after a query for another series, or after
    the platform has been handed an event whose rule, resource, version or evidence pin no longer
    matches anything this producer can justify. Every check here is pure and runs before the round's
    first read, first POST and first byte:

    * the entry's ``binding`` still describes the configured series (identity, SQL pin, every knob);
    * the event is still a *canonical* event at all — checked by ``state.validate_event``, the
      platform's own validator, so this file does not restate that schema and cannot drift from it;
    * it names this producer, the configured resource, the rule ``anomaly.<id>``, and the
      ``rule_version`` the **current** knobs produce — which is how a moved SQL digest or retuned
      ``k`` refuses a batch that would otherwise replay as a different opinion under the same id;
    * its evidence is still the reviewed metric read: one reference, the approved query kind, exactly
      the rule and sample it points at, for the same window;
    * its positions are positions this configuration can produce: ``last_acked_end``, ``anchored_at``
      and ``owed_end`` are whole seconds and a whole number of configured evaluations from the epoch,
      and where an ack and an owed attempt coexist the owed window is **exactly one** evaluation
      later. These three are checked for **every** entry state, including an entry that holds no
      payload at all — which is precisely the entry a failed read leaves, and precisely the one that
      would otherwise be answered by judging the later hour and never mentioning the hour in between;
    * the owed batch's own window is one configured evaluation long, epoch-aligned, and exactly one
      evaluation after the last acknowledged window — a batch for any other window is not the next
      thing owed, whatever its digests say about itself.

    Entries whose series left the configuration are **not** passed through here: their structural
    coherence is checked by ``load`` and retained, and there is no configuration left to compare them
    against. Deleting one stays an operator action.
    """
    series_id = _label(series['id'], 'series id')
    if entry['binding'] != series_binding(series):
        raise CursorRefusal(f'Anomaly series {series_id} changed underneath the cursor: its stored '
                            'verdicts belong to different configuration, so this round refuses '
                            'rather than mixing the two')
    if 'coverage' in entry:
        coverage = entry['coverage']
        threshold = coverage_threshold(series)
        if not threshold and coverage != coverage_initial():
            raise CursorRefusal('Disabled coverage series holds active coverage state')
        if (threshold and coverage['consecutive_unjudgeable'] >= threshold
                and not coverage['coverage_open']):
            raise CursorRefusal('Coverage threshold reached without an open episode')
        if coverage['previously_judgeable'] and entry['last_acked_end'] is None:
            raise CursorRefusal('Coverage history has no acknowledged window')
    evaluation = _check_evaluation(int(series['evaluation_seconds']))
    acked = _aligned_position(entry['last_acked_end'], evaluation, series_id, 'last_acked_end')
    _aligned_position(entry['anchored_at'], evaluation, series_id, 'anchored_at')
    owed = _aligned_position(entry['owed_end'], evaluation, series_id, 'owed_end')
    if acked is not None and owed is not None and owed != acked + evaluation:
        raise CursorRefusal(f'Anomaly series {series_id} owes an attempt '
                            f'{owed - acked} seconds after the window this cursor acknowledged, which '
                            f'is not one configured evaluation ({evaluation} seconds): answering it '
                            'would acknowledge the later window and skip the whole interval between '
                            'the two without ever naming it')
    pending = entry['pending']
    if pending is None:
        return
    if 'deliveries' in pending:
        after, status = coverage_transition(entry['coverage'], pending['outcome'],
                                            coverage_threshold(series))
        if after != pending['coverage_after']:
            raise CursorRefusal('Pending coverage transition disagrees with the acknowledged state')
        expected = ([('coverage', status)] if status else [])
        if pending['outcome'] in EVENT_VERDICTS:
            expected.append(('anomaly', 'firing' if pending['outcome'] == 'delivered' else 'resolved'))
        actual = [(item['event']['kind'], item['event']['status']) for item in pending['deliveries']]
        if actual != expected:
            raise CursorRefusal('Pending deliveries do not match the coverage transition')
        for delivery in pending['deliveries']:
            replay_coherent(series, {**entry, 'pending': delivery}, source=source, now=now,
                            rule_version=rule_version,
                            coverage_event=delivery['event']['kind'] == 'coverage')
        return
    event, sample = pending['event'], pending['sample']
    window = pending['window']
    start = _whole_second(window['start'], series_id, 'pending window start')
    end = _aligned_position(window['end'], evaluation, series_id, 'pending window end')
    if end - start != evaluation:
        raise CursorRefusal(f'Anomaly series {series_id} owes a batch whose window is not one '
                            f'configured evaluation ({evaluation} seconds) long')
    if acked is not None and end != acked + evaluation:
        raise CursorRefusal(f'Anomaly series {series_id} owes a batch that is not the next window '
                            'after the one this cursor acknowledged; catch-up is contiguous, so a '
                            'batch out of that order is not this producer\'s next delivery')
    try:
        validate_event(event, now)
    except StateError as exc:
        raise CursorRefusal(f'Anomaly series {series_id} owes a batch that is no longer a canonical '
                            f'event for this platform: {exc}') from None
    if event['source'] != source:
        raise CursorRefusal(f'Anomaly series {series_id} owes a batch written for another producer')
    rule = ('anomaly-coverage.' if coverage_event else 'anomaly.') + series_id
    if event['resource_id'] != series['resource_id']:
        raise CursorRefusal(f'Anomaly series {series_id} owes a batch for a resource the configuration '
                            'no longer names')
    if event['rule_id'] != rule or event['condition'] != rule:
        raise CursorRefusal(f'Anomaly series {series_id} owes a batch whose rule is not this series\'s')
    if event['rule_version'] != (coverage_version(series) if coverage_event else rule_version):
        raise CursorRefusal(f'Anomaly series {series_id} owes a batch judged by different '
                            'configuration (reviewed SQL or a knob moved), so replaying it would '
                            'post an old opinion under an id the new configuration owns')
    reference = event['evidence'][0]
    parameters = reference['parameters']
    if reference['query_type'] != REPLAY_QUERY_TYPE:
        raise CursorRefusal(f'Anomaly series {series_id} owes a batch whose evidence is not the '
                            f'reviewed {REPLAY_QUERY_TYPE} read')
    if set(parameters) != REPLAY_PARAMETERS or parameters['rule_id'] != rule:
        raise CursorRefusal(f'Anomaly series {series_id} owes a batch whose evidence parameters are '
                            'not this rule\'s sample reference')
    if parameters['sample_id'] != sample['sample_id']:
        raise CursorRefusal(f'Anomaly series {series_id} owes a batch whose event points at another '
                            'sample than the one it stores')
    if reference['window'] != window:
        raise CursorRefusal(f'Anomaly series {series_id} owes a batch whose evidence is quoted for a '
                            'different window than the one owed')


def window_text(end_s: int, evaluation: int) -> dict[str, str]:
    """Return the ``{'start', 'end'}`` pair of the window *ending* at *end_s*, as it is stored."""
    end = _instant_of(end_s)
    return {'start': utc_text(end - dt.timedelta(seconds=evaluation)), 'end': utc_text(end)}


def _instant_of(epoch_s: Any) -> dt.datetime:
    if isinstance(epoch_s, bool) or not isinstance(epoch_s, (int, float)):
        raise CursorRefusal('Anomaly window instants must be numbers')
    return dt.datetime.fromtimestamp(int(epoch_s), dt.timezone.utc)


def _check_evaluation(evaluation: Any) -> int:
    """Return *evaluation* as a whole number of seconds, refusing anything that is not one."""
    if isinstance(evaluation, bool) or not isinstance(evaluation, int) or evaluation < 1:
        raise CursorRefusal('Anomaly evaluation window must be a positive whole number of seconds')
    return evaluation


def _bump(state: dict[str, Any], field: str) -> int:
    """Add one to a lifetime counter and **saturate** it, never overflow it.

    Saturation is load-bearing and not tidiness: :data:`MAX_COUNT` is also the ceiling a *loaded*
    document is checked against, so a counter that walked past it would make every subsequent ``save``
    refuse — the cursor would become unwritable while still holding undelivered batches, and the
    producer would be unable to record the very refusals it was hitting. A count that stops at the
    ceiling is a **lower bound**, not an exact lifetime total: every report of a count that sits there
    — the per-series row of a round summary, the log line beside it — reads as "at least this many".
    An unwritable cursor is a stopped producer. And
    because no scheduling decision reads these counters, a saturated one cannot starve a series: the
    fairness marker is a name, not a number.
    """
    if state[field] < MAX_COUNT:
        state[field] += 1
    return state[field]


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse a JSON object that names one key twice: which of the two values is the record?"""
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise CursorRefusal('Anomaly cursor repeats a key, so it is not the document this '
                                'writer produced')
        seen.add(key)
    return dict(pairs)


def _served_marker(value: Any) -> str | None:
    """Return the round-robin marker, refusing one that is not an identifier this writer emitted.

    It is a name and not a count, which is what keeps the scheduler honest when the lifetime counters
    saturate: a marker can only ever point at a series, never rank one.
    """
    return None if value is None else _label(value, 'last-served marker')


def _label(value: Any, name: str) -> str:
    try:
        return label(value)
    except ValueError:
        raise CursorRefusal(f'Anomaly cursor {name} is not a bounded identifier') from None


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SHA256_TEXT.fullmatch(value):
        raise CursorRefusal(f'Anomaly cursor {name} is not a lowercase sha256')
    return value


def _instant(value: Any, name: str) -> dt.datetime:
    """Return the parsed instant, refusing text this writer could not have produced."""
    if not isinstance(value, str):
        raise CursorRefusal(f'Anomaly cursor {name} is not text')
    try:
        parsed = timestamp(value)
    except ValueError:
        raise CursorRefusal(f'Anomaly cursor {name} is not a UTC instant') from None
    if utc_text(parsed) != value:
        raise CursorRefusal(f'Anomaly cursor {name} is not in the form this writer emits')
    return parsed


def _whole_second(value: Any, series_id: str, field: str) -> int:
    """Return one stored instant as whole epoch seconds, **refusing** a fractional one.

    Not ``int(moment.timestamp())``: truncating a stored ``…T00:00:00.500000+00:00`` would quietly
    turn a position this producer could never have written into the second below it, and every
    alignment and ordering check that followed would be reasoning about an instant the file does not
    hold. A cursor is a record of window boundaries, and window boundaries are whole seconds.
    """
    moment = _instant(value, f'{field} of {series_id}')
    if moment.microsecond:
        raise CursorRefusal(f'Anomaly series {series_id} holds {field} at a fraction of a second; '
                            'window positions are whole seconds, and this reader does not round them '
                            'into existence')
    return int(moment.timestamp())


def _aligned_position(value: Any, evaluation: int, series_id: str, field: str) -> int | None:
    """Return one stored position as whole, epoch-aligned seconds, or None when the entry has none.

    "Aligned" here is a statement about the **configured** evaluation interval, so it can only be made
    by a caller holding the resolved series — which is why the check lives in the preflight and not in
    ``load``, and why it runs for an entry that holds no payload: a saved ``owed_end`` is the record of
    a window this producer began, and a beginning it could not have computed is a damaged position just
    as much as a damaged payload is.
    """
    if value is None:
        return None
    instant = _whole_second(value, series_id, field)
    if instant % evaluation:
        raise CursorRefusal(f'Anomaly series {series_id} holds {field} at a position that is not a '
                            f'whole number of configured evaluations ({evaluation} seconds) from the '
                            'epoch, so it is not a window boundary this producer could have reached')
    return instant


def _schema_version(value: Any) -> int:
    """Return the schema version, refusing a value that merely *equals* 1.

    `True == 1` in Python, and `1.0 == 1`, so an equality test alone lets a document written by
    something that guessed the field's type read as this producer's own. The counters below refuse
    booleans for the same reason: a cursor is a record, and "the version is the number one" and "the
    version is true" are different statements about who wrote it.
    """
    if (isinstance(value, bool) or not isinstance(value, int)
            or value not in (SCHEMA_VERSION, COVERAGE_SCHEMA_VERSION)):
        raise CursorRefusal('Anomaly cursor schema_version is not supported (1 or 2 required)')
    return value


def _validated_document(document: Any) -> dict[str, Any]:
    """Return *document* rebuilt from validated parts, refusing anything `load` would refuse."""
    if not isinstance(document, Mapping) or set(document) != CURSOR_KEYS:
        raise CursorRefusal('Anomaly cursor holds unknown or missing top-level keys')
    _schema_version(document['schema_version'])
    identity = _label(document['source'], 'producer identity')
    served = _served_marker(document['last_served'])
    entries = _validated_series(document, source=identity)
    # The marker naming an entry this file no longer holds is tolerated on purpose: an operator who
    # deleted a stale entry must not have to know that the round-robin position mentioned it. The
    # rotation starts from the head of the configuration instead (`rotation`).
    return {'schema_version': document['schema_version'], 'source': identity, 'last_served': served,
            'series': entries}


def _validated_series(document: Any, *, source: str) -> dict[str, Any]:
    entries = document['series']
    if not isinstance(entries, Mapping):
        raise CursorRefusal('Anomaly cursor series state is not an object')
    if not len(entries) <= MAX_ENTRIES:
        raise CursorRefusal(f'Anomaly cursor holds more than {MAX_ENTRIES} series entries')
    validated: dict[str, Any] = {}
    for series_id, state in entries.items():
        name = _label(series_id, 'series id')
        coverage = document['schema_version'] == COVERAGE_SCHEMA_VERSION
        keys = SERIES_STATE_KEYS | {'coverage'} if coverage else SERIES_STATE_KEYS
        if not isinstance(state, Mapping) or set(state) != keys:
            raise CursorRefusal(f'Anomaly cursor entry {name} holds unknown or missing fields')
        binding = _digest(state['binding'], f'binding of {name}')
        for field in ('last_acked_end', 'anchored_at', 'owed_end'):
            if state[field] is not None:
                _instant(state[field], f'{field} of {name}')
        if not isinstance(state['anchor_logged'], bool):
            raise CursorRefusal(f'Anomaly cursor entry {name} does not state its anchor plainly')
        counters: dict[str, int] = {}
        for field in ('delivered', 'no_verdict', 'refusals'):
            value = state[field]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_COUNT:
                raise CursorRefusal(f'Anomaly cursor entry {name} holds an impossible {field} count')
            counters[field] = value
        pending = state['pending']
        validated[name] = {'binding': binding, 'last_acked_end': state['last_acked_end'],
                           'anchored_at': state['anchored_at'], 'owed_end': state['owed_end'],
                           'anchor_logged': state['anchor_logged'],
                           'pending': None if pending is None else (
                               _validated_coverage_pending(pending, source) if coverage
                               else _validated_pending(pending, source)),
                           **counters}
        if coverage:
            validated[name]['coverage'] = _validated_coverage(state['coverage'])
        _coherent_ordering(name, validated[name])
    return validated


def _coherent_ordering(name: str, state: Mapping[str, Any]) -> None:
    """Refuse an entry whose own instants disagree with each other.

    A cursor is a *record of a sequence*, and the sequence has one direction: the anchor is the first
    window ever judged, an owed attempt and its batch sit strictly ahead of the last acknowledged
    window, and a batch always names the window its entry owes. Those are statements this file can
    check without knowing the configuration, which is why they are here rather than in the producer:
    a retained entry whose series left the configuration is checked to the same standard as a live
    one, and a restored or hand-edited document that contradicts itself is refused before it can be
    replayed as though it were a history.
    """
    acked, owed, anchor = state['last_acked_end'], state['owed_end'], state['anchored_at']
    if owed is not None and acked is not None and timestamp(owed) <= timestamp(acked):
        raise CursorRefusal(f'Anomaly cursor entry {name} owes a window at or behind the one it has '
                            'already acknowledged')
    if anchor is not None and acked is not None and timestamp(acked) < timestamp(anchor):
        raise CursorRefusal(f'Anomaly cursor entry {name} has acknowledged a window older than its '
                            'anchor, which this writer cannot have produced')
    pending = state['pending']
    if pending is None:
        return
    end = timestamp(pending['window']['end'])
    if owed is None or timestamp(owed) != end:
        raise CursorRefusal(f'Anomaly cursor entry {name} holds a pending batch for a window other '
                            'than the one it owes')
    if acked is not None and end <= timestamp(acked):
        raise CursorRefusal(f'Anomaly cursor entry {name} holds a batch for a window it has already '
                            'acknowledged')
    if anchor is not None and end < timestamp(anchor):
        raise CursorRefusal(f'Anomaly cursor entry {name} holds a batch older than its own anchor')


def _validated_pending(pending: Any, source: str, *, coverage: bool = False) -> dict[str, Any]:
    """Return one pending batch validated against the digests it carries.

    Structural only, and deliberately so: this function knows the file, not the configuration. That a
    stored batch still belongs to the series the operator has configured, at the knobs and the SQL pin
    it names, is checked by :func:`replay_coherent` before the producer spends a query on it.

    A batch always holds **both** bodies. Every anomaly verdict that reaches the wire is a sample and
    an event together (`_verdict` builds them as a pair, and a verdict with nothing to say is
    acknowledged without a batch), so a pending batch with no sample is not a cheap window — it is a
    record this producer did not write, and replaying it would post an event whose evidence reference
    points at a sample the platform was never given.
    """
    if not isinstance(pending, Mapping) or set(pending) != PENDING_KEYS:
        raise CursorRefusal('Anomaly pending batch holds unknown or missing fields')
    window = pending['window']
    if not isinstance(window, Mapping) or set(window) != WINDOW_KEYS:
        raise CursorRefusal('Anomaly pending window must carry exactly a start and an end')
    start = _instant(window['start'], 'pending window start')
    end = _instant(window['end'], 'pending window end')
    if start >= end:
        raise CursorRefusal('Anomaly pending window ends no later than it starts')
    sample, event = pending['sample'], pending['event']
    if sample is None:
        raise CursorRefusal('Anomaly pending batch holds an event with no evidence sample; every '
                            'anomaly verdict posts both bodies or nothing')
    if not isinstance(sample, Mapping) or not SAMPLE_REQUIRED <= set(sample):
        raise CursorRefusal('Anomaly pending evidence sample is not the stored sample contract')
    if len(wire_bytes(sample)) > MAX_SAMPLE_BYTES:
        raise CursorRefusal(f'Anomaly pending evidence sample exceeds {MAX_SAMPLE_BYTES} bytes')
    evidence_sha256 = payload_digest(sample)
    if evidence_sha256 != _digest(pending['evidence_sha256'], 'pending evidence digest'):
        raise CursorRefusal('Anomaly pending evidence does not re-serialise to the digest stored '
                            'beside it: this cursor is damaged, and its bytes stay as they are')
    if not isinstance(event, Mapping) or not EVENT_REQUIRED <= set(event):
        raise CursorRefusal('Anomaly pending event is not a canonical event')
    if len(wire_bytes(event)) > MAX_EVENT_BYTES:
        raise CursorRefusal(f'Anomaly pending event exceeds {MAX_EVENT_BYTES} bytes')
    if payload_digest(event) != _digest(pending['event_sha256'], 'pending event digest'):
        raise CursorRefusal('Anomaly pending event does not re-serialise to the digest stored beside '
                            'it: this cursor is damaged, and its bytes stay as they are')
    if event['source'] != source:
        raise CursorRefusal('Anomaly pending batch was written for a different producer identity')
    if event['resource_id'] is None:
        raise CursorRefusal('Anomaly pending batch carries an event with no resource to attach it to')
    if event['window'] != {'start': utc_text(start), 'end': utc_text(end)}:
        raise CursorRefusal('Anomaly pending event window differs from the window it is owed for')
    if (event['kind'] not in ({'anomaly', 'coverage'} if coverage else {'anomaly'})
            or event['status'] not in ('firing', 'resolved')):
        raise CursorRefusal('Anomaly pending batch holds a verdict this producer cannot make')
    references = event['evidence']
    if not isinstance(references, list) or not references or not isinstance(references[0], Mapping):
        raise CursorRefusal('Anomaly pending event carries no evidence reference')
    parameters = references[0].get('parameters')
    if not isinstance(parameters, Mapping):
        raise CursorRefusal('Anomaly pending event carries no evidence parameters')
    if parameters.get('sample_id') != (None if sample is None else sample['sample_id']):
        raise CursorRefusal('Anomaly pending batch pairs an event with evidence for another sample')
    return {'window': {'start': utc_text(start), 'end': utc_text(end)}, 'sample': sample,
            'event': dict(event), 'evidence_sha256': evidence_sha256,
            'event_sha256': payload_digest(event)}

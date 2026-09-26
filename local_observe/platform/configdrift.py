"""Snapshot-tree drift: the ``kind='drift'`` event this platform validated and nobody wrote.

What this reads is a **directory of configuration snapshots** that something else writes — one file
per ``<resource_id>/<name>``, where ``resource_id`` is a declared inventory UUID. Each round digests
the artifacts the operator named, compares each sha256 with the last one this producer reported, and
emits at most one canonical event per artifact whose digest moved. Nothing here writes to the tree:
the producer is a reader, and the only thing it owns is its cursor.

**The git question, decided: there is no git in this module.** v0.1 kept history by committing every
changed snapshot into a git-backed store and diffing the last two commits through one injected
``Runner`` seam with pinned commit identity. This product does neither, and both halves are
boundaries rather than omissions. (1) *History belongs to the operator's repository*: deployment separation puts
versioned operator data downstream of the product, so the tree arrives already versioned and this
module has no business re-versioning it, no ``.git`` to init and no identity to pin. (2) *A git
invocation is not evidence* — `docs/CONTRACTS.md` §4 makes an evidence reference something the
platform reauthorises on retrieval, and "whatever ``git show HEAD~1`` printed on that host under
whatever gitconfig" is not reauthorisable by anything. So the artifact **digest** is the evidence
(``artifact_sha256``, an approved parameter in ``state.validate_event``) and the previous digest comes
from this producer's own JSON cursor, not from a commit graph. No subprocess, no ``Runner``, no
``GIT_CONFIG_*`` hardening: there is no process to harden and no host configuration that can change
an answer.

What that trade costs, stated plainly: a **shorter memory than a commit log**. One digest per artifact
means "this file is not the file I last saw", never "this is the fourth revision today" and never
which commit or which operator made it. The unified diff is built against the retained last-seen text
— held in the cursor for that one purpose, up to :data:`MAX_SNAPSHOT_BYTES` — so deleting the cursor
re-baselines silently: the next round reports nothing until an artifact moves again.

Two refusals carry the rest of the design.

* **No event when nothing changed, and none on a first sighting either.** An artifact this producer
  has never seen has no previous digest, and "unseen" is not "changed": bringing the producer up over
  a populated tree delivers nothing, where v0.1's first capture committed and emitted. A baseline is
  not a drift finding. What closes the incident a real change opens is therefore **an acknowledgement
  and never a quiet round**: once a human files a durable acknowledgement naming the digest this
  artifact carries now and the rule the configuration maps to it, a **later** round emits one ordinary
  ``resolved`` drift event on the same condition key and ``state.Store.intake`` closes the incident the
  way it closes every other producer's. The whole path is off unless the configuration names an
  ``acknowledgements`` directory, and a stable round on its own still says nothing — the rule above
  stands. The record, the seven answers and every refusal are ``docs/units/drift-acknowledgement.md``.
* **Blindness is never silence.** A tree that cannot be read, or one artifact inside it that cannot,
  opens a ``coverage`` event about that source and closes it again when the file returns. The byte
  ceiling, the symlink refusal and the UTF-8 refusal all land on this path: the artifact is refused
  and its rule reports that it was not read. An undeclared ``resource_id`` is not on that path — it is
  a configuration error, and it refuses the whole round rather than letting a producer report drift
  about a resource that has no declared identity.

Everything leaves through the one legal factory, ``detections.event``, so the window, the evidence
reference and the expiry are canonical the way every other producer's are. Like the other optional
producers (event kinds), this one is **off unless ``LO_DRIFT_CONFIG`` names a JSON file**; with no file named
it logs one INFO line and exits 0, and it delivers nothing to any human channel — the delivery
decision belongs to the platform service, as it does for a Gatus result or an anomaly verdict.
"""
from __future__ import annotations

import datetime as dt
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from collections.abc import Callable, Mapping
from typing import Any, NamedTuple

from local_observe.credentials import read_credential
from local_observe.http import JsonClient, TransportError
from local_observe.inventory import index
from local_observe.inventory.validation import digest, timestamp, utc_text
from local_observe.log import get_logger
from .detections import event
from .owner import exclusive_owner
from .state import identifier, label

log = get_logger(__name__)

CONFIG_ENVIRONMENT = 'LO_DRIFT_CONFIG'
SOURCE_ENVIRONMENT = 'LO_DRIFT_SOURCE'
# The sleep between rounds, and the length of the window each round judges and each event carries.
DEFAULT_TICK_SECONDS = 300
# The floor keeps a round's window wider than the clock skew `validate_event` tolerates (60 s); the
# ceiling is 24 h because an event window may never exceed seven days and a drift report older than a
# day is a report about a tree nobody is watching any more.
TICK_LIMITS = (60, 86_400)
CONFIG_KEYS = frozenset({'root', 'cursor', 'resources', 'interval_seconds', 'acknowledgements'})
ENTRY_KEYS = frozenset({'resource_id', 'name', 'rule_id'})
MAX_CONFIG_BYTES = 262_144
# Per-artifact byte ceiling, and the reason it doubles as the cursor's retention ceiling: whatever
# this producer can read, it can remember, so there is no "digest but no text" state to explain.
# 64 KiB is the platform's own event ceiling (`state.validate_event`), which makes the number a
# boundary the rest of the product already agrees to rather than a new one.
MAX_SNAPSHOT_BYTES = 65_536
# Artifacts per process. The cursor holds one retained text each, so the bound is also the bound on
# the cursor's size (32 x 64 KiB plus JSON overhead, worst case about 2 MiB).
MAX_TRACKED = 32
MAX_CURSOR_BYTES = 4 * 1024 * 1024
# What one cursor entry must hold, and the one extra field it may hold: `ack_applied` is the identity of
# the last acknowledgement applied for that artifact, and nothing else may appear.
CURSOR_ENTRY_KEYS = frozenset({'sha256', 'text', 'unreadable'})
CURSOR_ENTRY_OPTIONAL = frozenset({'ack_applied'})
NAME_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
SHA256_TEXT = re.compile(r'[0-9a-f]{64}\Z')
# Fixed diagnosis codes: what an operator and a log line get, in place of exception text that can
# quote a path or a fragment of the file that caused it.
FAILURE_CODES: dict[type, str] = {FileNotFoundError: 'snapshot_absent',
                                  PermissionError: 'snapshot_unreadable',
                                  NotADirectoryError: 'snapshot_tree_absent',
                                  IsADirectoryError: 'snapshot_not_a_file'}
# The acknowledgement tree: one small JSON record per artifact, written by `drift_ack` from the
# operator's side and read here. 4 KiB is roomy against the record's own field limits (a digest, two
# labels, a 256-character reason) and still a sixteenth of the snapshot ceiling, because an
# acknowledgement states what a human accepted and is never a copy of the configuration it names.
MAX_ACK_BYTES = 4096
# The longest `reason` one record may carry, bounded so the audit detail stays a sentence rather than
# becoming a second place to store a file.
MAX_ACK_REASON_CHARS = 256
ACK_KEYS = frozenset({'schema_version', 'resource_id', 'name', 'rule_id', 'artifact_sha256', 'actor',
                      'reason', 'at'})
# The one word each artifact's row carries per round. `none` is the off switch or nothing filed;
# `stale`/`deferred`/`already` are a valid acknowledgement that closes nothing in this particular
# round; `applied` is the round that closed the incident; `refused` and `unreadable` are an
# instruction this producer could not trust. Not one of them silences a finding: a broken
# acknowledgement still reports the drift it was written about.
ACK_STATES = ('none', 'stale', 'deferred', 'applied', 'already', 'refused', 'unreadable')
# Fixed diagnosis codes for a refused acknowledgement, walked in insertion order exactly as
# `_failure_code` walks FAILURE_CODES — so the order **is** the contract: UnicodeDecodeError is a
# ValueError and must be named first or every non-UTF-8 record would be reported as `ack_invalid`.
# Absence is deliberately absent from this map: `read_acknowledgement` answers None for a file that is
# not there rather than raising, so there is no exception to code. The one refusal that is not an
# exception at all — a record naming a rule, a resource or a name other than the artifact whose path it
# sits at — logs the fixed word 'ack_rule_mismatch', spelled in `_acknowledgement_state`; it belongs to
# this vocabulary as much as the three codes below, and an operator greps for all four together.
ACK_FAILURE_CODES: dict[type, str] = {UnicodeDecodeError: 'ack_not_utf8',
                                      ValueError: 'ack_invalid',
                                      OSError: 'ack_unreadable'}


class Snapshot(NamedTuple):
    """One artifact as it sits on disk right now: the digest of its bytes and its decoded text."""

    resource_id: str
    name: str
    sha256: str
    text: str


class LastSeen(NamedTuple):
    """What the cursor remembers about one artifact: its last digest and the text behind it."""

    sha256: str
    text: str


class Comparison(NamedTuple):
    """The three facts one evaluation yields: previous digest, current digest, unified diff.

    `diff` is empty whenever `changed` is False, and also on a first sighting, where there is no
    earlier text to diff against. It is returned to the caller and never logged: a configuration
    snapshot is exactly the kind of file that holds a credential.
    """

    previous_sha256: str | None
    current_sha256: str
    diff: str

    @property
    def changed(self) -> bool:
        """True only when a baseline exists and its digest differs; a first sighting never changed."""
        return self.previous_sha256 is not None and self.previous_sha256 != self.current_sha256


class Acknowledgement(NamedTuple):
    """What one artifact's acknowledgement means this round: the reported word, and what to remember.

    `apply` is the record identity to store in the cursor's `ack_applied` when — and only when — this
    round applied it. Every other state leaves the cursor exactly as it stood, which is what keeps a
    stale instruction inert instead of spending it.
    """

    state: str
    apply: str | None


def safe_component(value: Any, field: str) -> str:
    """Return *value* as one path-safe snapshot component, refusing anything that is not.

    A name is the only part of a snapshot path an operator types freely, and a name carrying a
    separator turns "read this artifact" into "read a file outside the tree". The separators are
    refused by name so the message says what was wrong, and the pattern is what refuses everything
    else (``..``, a leading ``-`` that a tool would read as a flag, control characters, a dot-only
    name, an empty one).
    """
    if not isinstance(value, str):
        raise ValueError(f'Drift {field} must be text')
    if not value or value in ('.', '..'):
        raise ValueError(f'Drift {field} is empty or a directory reference')
    if '/' in value or '\\' in value or os.sep in value or (os.altsep and os.altsep in value):
        raise ValueError(f'Drift {field} contains a path separator')
    if '\x00' in value or value.startswith('-'):
        raise ValueError(f'Drift {field} is not a safe file name')
    if not NAME_PATTERN.fullmatch(value):
        raise ValueError(f'Drift {field} holds characters this producer will not open')
    return value


def entry_key(entry: Mapping[str, Any]) -> str:
    """Return the cursor key for one configured artifact; it is a label, never a path."""
    return f"{entry['resource_id']}/{entry['name']}"


def _absolute(value: Any, field: str) -> Path:
    """Return *value* as an absolute path, refusing a relative one.

    A relative root means "wherever the process happened to start", which for a container is a
    mount point and for a hand-run command is a surprise. The operator names the directory.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'Drift configuration {field} must name a path')
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f'Drift configuration {field} must be an absolute path')
    return path


def load_config(path: Path | str) -> dict[str, Any]:
    """Read and validate the JSON document ``LO_DRIFT_CONFIG`` names; every refusal names a field.

    The document is ``{"root": <dir>, "cursor": <file>, "resources": [{"resource_id", "name",
    "rule_id"}], "interval_seconds": <int>, "acknowledgements": <dir>}``. Nothing is defaulted except
    the interval and the acknowledgement directory: a producer that quietly dropped the artifact it
    could not parse would report "no drift" about a file it never read, so every malformed field raises
    here rather than at the first round.

    ``acknowledgements`` is the optional root of the operator's acknowledgement tree (task drift resolution). When
    it is absent the whole resolve path is off and the answer is ``None`` — the producer behaves
    exactly as it did before the key existed. When present it is an absolute directory like ``root``,
    and it is deliberately **not** part of the cursor binding: see `cursor_binding`.

    ``resource_id`` must be a canonical UUID and is checked against the declared index on every round
    (the same resolution ``detections.evaluate`` performs); ``rule_id`` is the event's rule *and* its
    condition identity, so it must stay a bounded label with ``.coverage`` appended, and it must be
    unique across the file. Two artifacts may share a resource — a device with a running and a
    startup config — but never a rule, and never the same path twice.
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
    if not isinstance(document, dict) or set(document) - CONFIG_KEYS:
        raise ValueError(f'Drift configuration holds unknown keys or is not an object; expected '
                         f'{", ".join(sorted(CONFIG_KEYS))}')
    missing = CONFIG_KEYS - {'interval_seconds', 'acknowledgements'} - set(document)
    if missing:
        raise ValueError(f'Drift configuration is missing {", ".join(sorted(missing))}')
    interval = document.get('interval_seconds', DEFAULT_TICK_SECONDS)
    if (isinstance(interval, bool) or not isinstance(interval, int)
            or not TICK_LIMITS[0] <= interval <= TICK_LIMITS[1]):
        raise ValueError(f'Drift interval_seconds must be a whole number of seconds from '
                         f'{TICK_LIMITS[0]} to {TICK_LIMITS[1]}')
    entries = document['resources']
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_TRACKED:
        raise ValueError(f'Drift resources must be a list of 1..{MAX_TRACKED} artifacts')
    resources: list[dict[str, Any]] = []
    rules: set[str] = set()
    keys: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise ValueError(f'Drift resource must name exactly {", ".join(sorted(ENTRY_KEYS))}')
        try:
            resource_id = identifier(entry['resource_id'])
        except ValueError:
            raise ValueError('Drift resource_id must be a canonical declared UUID') from None
        name = safe_component(entry['name'], 'name')
        rule = entry['rule_id']
        try:
            label(rule)
            label(rule + '.coverage')
        except ValueError:
            raise ValueError(f'Drift rule_id {rule!r} is not a bounded identifier') from None
        key = entry_key({'resource_id': resource_id, 'name': name})
        if rule in rules:
            raise ValueError(f'Drift rule_id {rule} names two artifacts; one condition per artifact')
        if key in keys:
            raise ValueError(f'Drift artifact {key} is named twice')
        rules.add(rule)
        keys.add(key)
        resources.append({'resource_id': resource_id, 'name': name, 'rule_id': rule})
    # An absent key is the off switch; a present one must be a path. `None` written into the document is
    # a refusal rather than a second spelling of "off", because `_absolute` says which field it means.
    acknowledgements = (_absolute(document['acknowledgements'], 'acknowledgements')
                        if 'acknowledgements' in document else None)
    return {'root': _absolute(document['root'], 'root'), 'cursor': _absolute(document['cursor'], 'cursor'),
            'interval_seconds': int(interval), 'resources': resources,
            'acknowledgements': acknowledgements}


def producer_config(environment: Mapping[str, str] | None = None) -> dict[str, Any] | None:
    """Return the validated configuration, or None when the producer is not configured at all.

    An unset or blank ``LO_DRIFT_CONFIG`` is the documented off switch and answers one INFO line
    naming the variable — the event kinds rule, so every optional producer here means "off" the same way.
    A file that is named and cannot be read or parsed is not off: it raises, and `main` exits 1,
    because a producer that survived a broken config would be reporting "no drift" about a tree it
    never opened.
    """
    environ = os.environ if environment is None else environment
    raw = (environ.get(CONFIG_ENVIRONMENT) or '').strip()
    if not raw:
        log.info('Config-drift producer is off; no configuration named',
                 extra={'variable': CONFIG_ENVIRONMENT})
        return None
    return load_config(raw)


def read_snapshot(root: Path | str, resource_id: str, name: str) -> Snapshot:
    """Return the artifact at ``<root>/<resource_id>/<name>``, or refuse it.

    Three refusals, all raised rather than skipped: **no tree** (the mount is not there), **a
    symlink** (a snapshot must be a file inside the tree the operator pointed at, not a link that
    leaves it) and **more than :data:`MAX_SNAPSHOT_BYTES` or not UTF-8** (a diff over bytes no
    reviewer can read is not a diff). The digest is taken over the bytes as stored, opened in binary
    on purpose: a tool that translated newlines on the way in would make one file digest differently
    on two hosts, which is how a drift producer invents its own findings.
    """
    directory = Path(root)
    if not directory.is_dir():
        raise NotADirectoryError(f'No snapshot tree at {directory}')
    target = directory / resource_id / name
    if target.is_symlink():
        raise ValueError('Refusing a snapshot that is a symlink out of the tree')
    if not target.is_file():
        raise FileNotFoundError(f'No snapshot file for {resource_id}/{name}')
    with target.open('rb') as stream:
        raw = stream.read(MAX_SNAPSHOT_BYTES + 1)
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise ValueError(f'Snapshot exceeds the {MAX_SNAPSHOT_BYTES}-byte ceiling')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('Snapshot is not UTF-8 text') from None
    return Snapshot(resource_id=resource_id, name=name, sha256=hashlib.sha256(raw).hexdigest(), text=text)


def acknowledgement_path(root: Path | str, resource_id: str, name: str) -> Path:
    """Return ``<root>/<resource_id>/<name>.json``, the one place an artifact's acknowledgement sits.

    Two components, both already checked elsewhere: ``resource_id`` is a canonical UUID (`identifier`)
    and ``name`` passed this module's own `safe_component`, the same rule every configured name passes
    through at `load_config`, so no separator, no ``..`` and no flag-looking name can arrive here. The
    tree is operator-owned: this producer reads it and — exactly as for the snapshot tree — never
    writes it. `drift_ack` writes it, from the operator's side of the mount.
    """
    return Path(root) / resource_id / f'{name}.json'


def validate_acknowledgement(document: Any) -> dict[str, Any]:
    """Return the normalised form of one acknowledgement record; every refusal names a field.

    The record is what a human promised, so it is small and closed: the artifact it belongs to
    (``resource_id`` and ``name``, the pair that is also its path, held to the same `safe_component`
    rule a configured name already passes), the rule that was configured when they looked
    (``rule_id``), the exact bytes they accepted (``artifact_sha256``), who they are (``actor``, a
    bounded label), why (``reason``, 1 to :data:`MAX_ACK_REASON_CHARS` characters with no control
    character, so one record cannot smuggle a file or a second log line) and when (``at``, a
    timezone-aware timestamp). ``schema_version`` is 1 and nothing else is accepted, known or unknown.

    What is deliberately **not** in it: the artifact's text, a path, a credential, or any promise about
    later bytes. An acknowledgement is an instruction about one digest, and keeping it to that is what
    makes a stale one harmless.
    """
    if not isinstance(document, dict) or set(document) != ACK_KEYS:
        raise ValueError(f'Drift acknowledgement must name exactly {", ".join(sorted(ACK_KEYS))}')
    version = document['schema_version']
    if isinstance(version, bool) or version != 1:
        raise ValueError('Drift acknowledgement schema_version must be 1')
    try:
        resource_id = identifier(document['resource_id'])
    except ValueError:
        raise ValueError('Drift acknowledgement resource_id must be a canonical declared UUID') from None
    name = safe_component(document['name'], 'name')
    rule = document['rule_id']
    try:
        label(rule)
    except ValueError:
        raise ValueError(f'Drift acknowledgement rule_id {rule!r} is not a bounded identifier') from None
    actor = document['actor']
    try:
        label(actor)
    except ValueError:
        raise ValueError('Drift acknowledgement actor is not a bounded identifier') from None
    checksum = document['artifact_sha256']
    if not isinstance(checksum, str) or not SHA256_TEXT.fullmatch(checksum):
        raise ValueError('Drift acknowledgement artifact_sha256 must be 64 lowercase hex characters')
    moment = document['at']
    try:
        timestamp(moment)
    except ValueError:
        raise ValueError('Drift acknowledgement at is not a timezone-aware ISO timestamp') from None
    reason = document['reason']
    if (not isinstance(reason, str) or not 1 <= len(reason) <= MAX_ACK_REASON_CHARS
            or any(character < ' ' or character == '\x7f' for character in reason)):
        raise ValueError(f'Drift acknowledgement reason must be 1..{MAX_ACK_REASON_CHARS} characters '
                         'and hold no control character')
    return {'schema_version': 1, 'resource_id': resource_id, 'name': name, 'rule_id': rule,
            'artifact_sha256': checksum, 'actor': actor, 'reason': reason, 'at': moment}


def read_acknowledgement(root: Path | str, resource_id: str,
                         name: str) -> tuple[dict[str, Any], str] | None:
    """Return ``(record, identity)`` for one artifact's acknowledgement, or None when none was filed.

    An absent file is the ordinary case and answers ``None`` (the round reports ``ack == 'none'``).
    Everything else that is wrong **raises**, because a record that exists and cannot be parsed is an
    instruction the operator asked this producer to follow and cannot: a symlink (the same refusal as a
    snapshot — this tree is not the producer's to follow out of), anything that is not a regular file,
    more than :data:`MAX_ACK_BYTES`, bytes that are not UTF-8 (left as ``UnicodeDecodeError``, which is
    the case :data:`ACK_FAILURE_CODES` names ``ack_not_utf8`` for — rewriting it into a ValueError would
    lose the distinction), text that is not JSON, and any record `validate_acknowledgement` refuses.

    The identity is ``digest(record)`` over the *validated* record, not the bytes on disk: whitespace
    and key order cannot turn one promise into two, and the same digest acknowledged again at a later
    ``at`` is a **new** record with a new identity. That is what lets one artifact be acknowledged twice
    over and closes a second incident with the second record.
    """
    target = acknowledgement_path(root, resource_id, name)
    if target.is_symlink():
        raise ValueError('Refusing a drift acknowledgement that is a symlink out of the tree')
    if not target.exists():
        return None
    if not target.is_file():
        raise ValueError('Drift acknowledgement is not a regular file')
    with target.open('rb') as stream:
        raw = stream.read(MAX_ACK_BYTES + 1)
    if len(raw) > MAX_ACK_BYTES:
        raise ValueError(f'Drift acknowledgement exceeds the {MAX_ACK_BYTES}-byte ceiling')
    validated = validate_acknowledgement(json.loads(raw.decode('utf-8')))
    return validated, digest(validated)


def compare(previous: LastSeen | None, current: Snapshot) -> Comparison:
    """Digest the change between the last-seen text and the current one, with a unified diff.

    ``difflib`` rather than a diff tool, exactly as v0.1 chose: the output is deterministic and no
    external binary gets to decide what a change looked like. Headers name the artifact and the two
    digests (first twelve hex characters) so a diff pasted into a review says what it is a diff of,
    which is the role v0.1's commit ids played. A first sighting is not a change.
    """
    if previous is None or previous.sha256 == current.sha256:
        return Comparison(None if previous is None else previous.sha256, current.sha256, '')
    path = f'{current.resource_id}/{current.name}'
    lines = difflib.unified_diff(previous.text.splitlines(keepends=True), current.text.splitlines(keepends=True),
                                 fromfile=f'{path}@{previous.sha256[:12]}', tofile=f'{path}@{current.sha256[:12]}')
    return Comparison(previous.sha256, current.sha256, ''.join(lines))


def drift_finding(source: str, entry: Mapping[str, Any], window: Mapping[str, str],
                  comparison: Comparison) -> dict[str, Any]:
    """Build the one event a changed artifact earns: ``kind='drift'``, evidence is its digest.

    ``query_type='observed-snapshot'`` and not ``metric-threshold``: the verdict is "the bytes of this
    artifact are not the bytes I last saw", which is the identity of a snapshot, not a number crossing
    a limit. ``metric-threshold`` would be accepted by `validate_event` and would be a lie — there is
    no threshold in this producer and no sample to post: ``state.put_evidence`` keeps only boolean or
    numeric ``value`` fields, so a digest has no legal sample form and no row is fabricated for it. The
    reference therefore carries what the platform can reauthorise — the artifact and the rule that
    watched it, the same pair the Sigma runner puts in ``artifact_sha256``/``rule_id``.

    Severity is the factory default, ``warning``, which is also what v0.1 stamped on its
    ``config.changed`` event: a snapshot that moved is not by itself critical, and the caller who
    decides that a particular artifact is critical config does so in the platform, not here.
    ``previous_sha256`` is deliberately absent: no approved evidence parameter names a prior digest,
    and inventing a slot for it would be an unapproved parameter with a different name.
    """
    return event(source, entry['resource_id'], entry['rule_id'], 'drift', 'firing', dict(window),
                 {'rule_id': entry['rule_id'], 'artifact_sha256': comparison.current_sha256},
                 query_type='observed-snapshot')


def coverage_finding(source: str, entry: Mapping[str, Any], window: Mapping[str, str],
                     status: str) -> dict[str, Any]:
    """Say this artifact could not be read (`firing`) or can be read again (`resolved`).

    Same shape as the coverage half of ``detections.evaluate``: its own rule name (``<rule>.coverage``,
    so it holds a different condition key from the drift finding and can never mask it), a
    ``source-heartbeat`` reference and the parent rule as its parameter.
    """
    return event(source, entry['resource_id'], entry['rule_id'] + '.coverage', 'coverage', status,
                 dict(window), {'rule_id': entry['rule_id']}, query_type='source-heartbeat')


def acknowledged_finding(source: str, entry: Mapping[str, Any], window: Mapping[str, str],
                         artifact_sha256: str) -> dict[str, Any]:
    """Say a named human saw this digest and accepted it: the ``resolved`` half of the drift condition.

    Same source, resource, rule, rule version and window as `drift_finding` — that is the whole point,
    because ``Store.intake`` keys a condition on ``[source, rule_id, rule_version, resource_id,
    condition]`` and closes an incident only on that key. A different rule name would open a second
    condition and leave the drift incident open forever, which is the defect drift resolution exists to fix.

    It goes out on a **stable** round and never beside the firing event: `detections.event` derives
    ``source_event_id`` from rule, version, resource and window, so both would carry one id and the
    second would be refused by ``state.py`` as `Event retry changed contents`, taking the whole round
    down with it. An acknowledgement that matches while the digest is moving is therefore ``deferred``
    to the next round. Severity is the factory default — ``info`` for a resolved verdict — because this
    module names no loudness of its own, which is the rule
    ``tests/test_event_vocabulary.py`` pins by grep.
    """
    return event(source, entry['resource_id'], entry['rule_id'], 'drift', 'resolved', dict(window),
                 {'rule_id': entry['rule_id'], 'artifact_sha256': artifact_sha256},
                 query_type='observed-snapshot')


def _window(now: dt.datetime, interval_seconds: int) -> dict[str, str]:
    """Return the aligned ``(end - interval, end]` window this round judges and its events carry.

    Aligned to the interval, so a round that is recomputed after a failed delivery produces the same
    window and so the same ``source_event_id``: the platform folds the retry into the row it already
    holds instead of opening a second incident. The observation instant is that watermark and not the
    file's mtime, because a restore, a ``git checkout`` or an ``rsync`` all set an mtime that says
    something which never happened.
    """
    end = dt.datetime.fromtimestamp(int(now.timestamp()) // interval_seconds * interval_seconds,
                                    dt.timezone.utc)
    return {'start': utc_text(end - dt.timedelta(seconds=interval_seconds)), 'end': utc_text(end)}


def cursor_binding(config: Mapping[str, Any]) -> str:
    """Return the digest of *what is watched* — the tree and the artifact set, not the tick rate.

    Deliberately excludes ``interval_seconds``, the rule names and the ``acknowledgements`` root: those
    change how a verdict is reported, or where an operator's instruction is filed, not which bytes a
    digest belongs to, and a cursor must not be thrown away for a retune. It includes the root and the
    ``resource_id``/``name`` pairs, because those are what a stored digest is a statement about.

    Putting the acknowledgement root into this binding would be a trap rather than a tightening: it
    would change the binding the moment an operator turned acknowledgements on, and every existing
    cursor would then be **refused** — `load_cursor` raises 'Drift cursor belongs to a different
    snapshot tree or artifact set; remove it to re-baseline', that refusal propagates out of `tick`, and
    `main` logs a warning and repeats the round, so the producer delivers nothing at all until an
    operator deletes the cursor — which loses every stored digest and re-baselines the whole tree.
    """
    watched = sorted([[entry['resource_id'], entry['name']] for entry in config['resources']])
    return digest([str(config['root']), watched])


def _remembered(record: Mapping[str, Any] | None) -> LastSeen | None:
    """Return the baseline held for one artifact, or None when nothing is remembered about it."""
    if record is None or record.get('sha256') is None:
        return None
    return LastSeen(str(record['sha256']), str(record['text']))


def _carry_ack(target: dict[str, Any], record: Mapping[str, Any] | None, applied: str | None) -> None:
    """Keep a cursor entry's acknowledgement marker across the rebuild, unless this round spent a new one.

    Both paths through `tick` build the new entry from scratch, so a marker that is not copied forward is
    simply forgotten — and a forgotten marker makes the next round apply the same acknowledgement again
    and re-emit a resolve on a condition the platform already closed. Written only when there is one, so
    an artifact nobody has ever acknowledged keeps exactly the three-key entry it always had.
    """
    marker = applied or (record or {}).get('ack_applied')
    if marker:
        target['ack_applied'] = marker


def load_cursor(path: Path | str, config: Mapping[str, Any]) -> dict[str, Any]:
    """Return ``{'schema_version', 'binding', 'seen'}``; refuse a cursor from another configuration.

    A cursor whose binding differs is never silently re-baselined: a record of "what the digest was
    before" read from a different root or a different artifact set is precisely how a monitor
    manufactures drift out of an unrelated edit. The refusal says so, and removing the file is the
    operator's answer (the next round then re-baselines and reports nothing until an artifact moves).
    The structure is checked field by field and fails closed for the same reason.

    One entry field is optional: ``ack_applied``, the identity of the last acknowledgement this producer
    actually applied for that artifact. It is what makes an acknowledgement spendable once — without it
    a stable, acknowledged artifact would be resolved on every round after the first — and it is a
    digest or nothing. An artifact that has never been acknowledged keeps the three-key entry it always
    had, so turning the feature on changes no existing cursor byte.
    """
    candidate = Path(path)
    expected = cursor_binding(config)
    if not candidate.exists():
        return {'schema_version': 1, 'binding': expected, 'seen': {}}
    with candidate.open('rb') as stream:
        raw = stream.read(MAX_CURSOR_BYTES + 1)
    if len(raw) > MAX_CURSOR_BYTES:
        raise ValueError(f'Drift cursor exceeds {MAX_CURSOR_BYTES} bytes')
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ValueError('Drift cursor is not JSON') from None
    if (not isinstance(document, dict) or set(document) != {'schema_version', 'binding', 'seen'}
            or document['schema_version'] != 1 or not isinstance(document['seen'], dict)
            or len(document['seen']) > MAX_TRACKED):
        raise ValueError('Unsupported drift cursor document')
    if document['binding'] != expected:
        raise ValueError('Drift cursor belongs to a different snapshot tree or artifact set; '
                         'remove it to re-baseline')
    for record in document['seen'].values():
        if (not isinstance(record, dict) or not CURSOR_ENTRY_KEYS <= set(record)
                or set(record) - CURSOR_ENTRY_KEYS - CURSOR_ENTRY_OPTIONAL):
            raise ValueError('Drift cursor holds an unreadable entry shape')
        checksum, text, unreadable = record['sha256'], record['text'], record['unreadable']
        if 'ack_applied' in record:
            applied = record['ack_applied']
            if not isinstance(applied, str) or not SHA256_TEXT.fullmatch(applied):
                raise ValueError('Drift cursor holds an acknowledgement marker that is not a digest')
        if not isinstance(unreadable, bool) or not (text is None or isinstance(text, str)):
            raise ValueError('Drift cursor holds an unreadable entry shape')
        if isinstance(text, str) and len(text.encode()) > MAX_SNAPSHOT_BYTES:
            raise ValueError('Drift cursor retains more text than this producer could ever have read')
        if checksum is None:
            if not unreadable:
                raise ValueError('Drift cursor holds a digestless entry that claims to be readable')
        elif not isinstance(checksum, str) or not SHA256_TEXT.fullmatch(checksum) or not isinstance(text, str):
            raise ValueError('Drift cursor holds a digest with no text behind it')
    return document


def save_cursor(path: Path | str, value: Mapping[str, Any]) -> None:
    """Write the cursor atomically and privately: it holds configuration text, not only digests.

    The same durability sequence ``detection_worker.save`` uses — temporary file, ``fsync``, atomic
    ``os.replace``, directory ``fsync`` where the platform has one — with the one difference that is
    the reason this function exists instead of importing that one: the file is created 0600 (and
    re-set on overwrite), because the retained last-seen text of every artifact is configuration
    content and may carry exactly the credentials the tree it mirrors carries. The parent
    directory is created when absent, as ``Store`` does for its own database: the operator names
    a path, and a producer that refused to start because of one missing directory would be
    asking to be pointed somewhere unsafe instead.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    os.replace(temporary, destination)
    if os.name != 'nt':
        handle = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(handle)
        finally:
            os.close(handle)


def _failure_code(exc: Exception) -> str:
    """Return the fixed diagnosis code for a snapshot read that failed; never the exception text."""
    for kind, code in FAILURE_CODES.items():
        if isinstance(exc, kind):
            return code
    return 'snapshot_refused'


def _ack_failure_code(exc: Exception) -> str:
    """Return the fixed diagnosis code for a refused acknowledgement; never the exception text.

    The same first-match walk `_failure_code` performs, over :data:`ACK_FAILURE_CODES`, for the same
    reason: an operator's `OSError` message can quote the path of the file they mis-edited, and a log
    line is not where a path belongs. The exception **class** is what selects the code.
    """
    for kind, code in ACK_FAILURE_CODES.items():
        if isinstance(exc, kind):
            return code
    return 'ack_refused'


def _acknowledgement_state(entry: Mapping[str, Any], record: Mapping[str, Any] | None,
                           current: Snapshot, changed: bool,
                           root: Path | str | None) -> Acknowledgement:
    """Decide the one `ack` word this readable artifact gets this round; refuse, never raise.

    The order is the rule, and each state means something an operator reads:

    * ``none`` — no acknowledgement directory configured, or none filed for this artifact. The path is
      off and this producer behaves exactly as it did before it existed.
    * ``refused`` — the file exists and cannot be trusted (unreadable, not UTF-8, not JSON, a field
      this reader will not accept) or it names a resource, a name or a rule other than the artifact
      whose path it sits at. Logged with one fixed code from :data:`ACK_FAILURE_CODES` (or
      ``'ack_rule_mismatch'``, which is not an exception at all) and never with the exception text.
    * ``stale`` — the record names a digest that is not the one on disk now. Inert: it closes nothing
      and suppresses nothing, and it never hides the change that made it stale.
    * ``already`` — this exact record has already been applied, which is the difference between closing
      one incident and re-resolving the same condition on every round forever.
    * ``deferred`` — the digest moved this round, so the firing event owns this window's
      ``source_event_id`` and the resolve must wait for the next round (see `acknowledged_finding`).
    * ``applied`` — readable, matching, unspent and stable: this round closes the incident.

    A malformed or stale acknowledgement is **never** a ``coverage`` event: coverage is a claim about
    the snapshot source — "this producer could not see the artifact" — and a broken operator instruction
    is not blindness about it. The verdict this round files stands exactly as it would with no
    acknowledgement tree at all.
    """
    if root is None:
        return Acknowledgement('none', None)
    try:
        loaded = read_acknowledgement(root, entry['resource_id'], entry['name'])
    except (OSError, ValueError) as exc:
        log.warning('Drift acknowledgement refused',
                    extra={'code': _ack_failure_code(exc), 'artifact': entry_key(entry)})
        return Acknowledgement('refused', None)
    if loaded is None:
        return Acknowledgement('none', None)
    document, identity = loaded
    if (document['resource_id'] != entry['resource_id'] or document['name'] != entry['name']
            or document['rule_id'] != entry['rule_id']):
        # A record must name the artifact whose path it sits at, and the rule that artifact is watched
        # by now: acknowledging a change under a rule the configuration no longer maps to it would let
        # one file close an incident belonging to another. That is an operator error, not an
        # acknowledgement, and it is the one refusal with no exception behind it.
        log.warning('Drift acknowledgement refused',
                    extra={'code': 'ack_rule_mismatch', 'artifact': entry_key(entry)})
        return Acknowledgement('refused', None)
    if document['artifact_sha256'] != current.sha256:
        return Acknowledgement('stale', None)
    if identity == (record or {}).get('ack_applied'):
        return Acknowledgement('already', None)
    if changed:
        return Acknowledgement('deferred', None)
    return Acknowledgement('applied', identity)


def tick(index_path: Path | str, config: Mapping[str, Any], cursor_path: Path | str,
         deliver: Callable[[dict[str, Any]], None], *, now: dt.datetime,
         source: str) -> dict[str, Any]:
    """Compare the tree with the cursor, deliver what moved, and advance the cursor only after.

    One round, no loop and no client of its own: `deliver` is called once per event and must raise on
    any refusal. The cursor is written **last**, so a refused or crashed delivery is recomputed on the
    next round instead of being half-remembered — and because the window is aligned, that recomputation
    yields the same ``source_event_id`` and the platform folds it into the row it already holds.

    Outcomes, in the summary's ``result`` field and in the caller's one log line: ``idle`` (every
    artifact readable and unchanged; may still have baselined new ones), ``delivered`` (at least one
    event went out and every artifact was readable), ``unreadable`` (something could not be read this
    round — the dominant answer, so a round that both reported a change and lost a file says
    ``unreadable``). An undeclared resource raises out of the whole round: identity is not something a
    partial verdict may be built on.

    The summary carries the `window` judged, the `events` delivered, one `evaluations` row per
    artifact (both digests, the diff, the fixed `error` code when the artifact was refused, and the one
    `ack` word from `ACK_STATES` describing what its acknowledgement meant this round) and the
    `changed`/`baselined`/`unreadable`/`acknowledged` counts the caller's one log line is built from.
    Nothing in it holds a credential or a file's text except the `diff` field, which `lo-platform drift`
    prints only when the operator asks for it.
    """
    path = Path(cursor_path)
    cursor = load_cursor(path, config)
    seen: Mapping[str, Any] = cursor['seen']
    window = _window(now, int(config['interval_seconds']))
    with index.readonly(index_path) as connection:
        for entry in config['resources']:
            if index.resolve(connection, resource_id=entry['resource_id'])['status'] != 'resolved':
                raise ValueError('Detection resource is not declared')
    events: list[dict[str, Any]] = []
    evaluations: list[dict[str, Any]] = []
    remembered: dict[str, dict[str, Any]] = {}
    acknowledgements = config.get('acknowledgements')
    dirty = False
    for entry in config['resources']:
        key = entry_key(entry)
        record = seen.get(key)
        artifact = {'resource_id': entry['resource_id'], 'name': entry['name'], 'rule_id': entry['rule_id'],
                    'previous_sha256': None, 'current_sha256': None, 'changed': False, 'diff': '',
                    'diff_lines': 0, 'error': None, 'error_class': None, 'ack': None}
        try:
            current = read_snapshot(config['root'], entry['resource_id'], entry['name'])
        except (OSError, ValueError) as exc:
            artifact['error'], artifact['error_class'] = _failure_code(exc), type(exc).__name__
            # An artifact that could not be read has no digest to match an acknowledgement against, so
            # nothing is read for it either: the answer is `unreadable` and the record waits.
            artifact['ack'] = 'unreadable'
            if not (record or {}).get('unreadable'):
                events.append(coverage_finding(source, entry, window, 'firing'))
            # Keep the digest from before the gap: an artifact that changed while it was unreadable is
            # still drift, and forgetting it is how a monitor turns an outage into a clean sheet. The
            # acknowledgement marker is carried forward for the same reason — losing it would re-apply
            # a spent acknowledgement and re-emit a resolve every round.
            remembered[key] = {'sha256': (record or {}).get('sha256'), 'text': (record or {}).get('text'),
                               'unreadable': True}
            _carry_ack(remembered[key], record, None)
            evaluations.append(artifact)
            dirty = dirty or remembered[key] != record
            continue
        comparison = compare(_remembered(record), current)
        artifact.update({'previous_sha256': comparison.previous_sha256,
                         'current_sha256': comparison.current_sha256, 'changed': comparison.changed,
                         'diff': comparison.diff, 'diff_lines': comparison.diff.count('\n')})
        if comparison.changed:
            events.append(drift_finding(source, entry, window, comparison))
        if (record or {}).get('unreadable'):
            events.append(coverage_finding(source, entry, window, 'resolved'))
        acknowledgement = _acknowledgement_state(entry, record, current, comparison.changed,
                                                 acknowledgements)
        artifact['ack'] = acknowledgement.state
        if acknowledgement.state == 'applied':
            events.append(acknowledged_finding(source, entry, window, current.sha256))
        remembered[key] = {'sha256': current.sha256, 'text': current.text, 'unreadable': False}
        _carry_ack(remembered[key], record, acknowledgement.apply)
        evaluations.append(artifact)
        dirty = dirty or remembered[key] != record
    for item in events:
        deliver(item)
    if dirty:
        save_cursor(path, {'schema_version': 1, 'binding': cursor['binding'], 'seen': remembered})
    return {'result': ('unreadable' if any(item['error'] for item in evaluations)
                       else 'delivered' if events else 'idle'),
            'window': window, 'events': events, 'evaluations': evaluations,
            'changed': sum(1 for item in evaluations if item['changed']),
            'baselined': sum(1 for item in evaluations if item['previous_sha256'] is None and not item['error']),
            'unreadable': sum(1 for item in evaluations if item['error']),
            'acknowledged': sum(1 for item in evaluations if item['ack'] == 'applied')}


def main() -> int:
    """Run the producer loop; exit 0 without touching the network when nothing is configured.

    Identity comes from ``LO_DRIFT_SOURCE`` and must match the producer token's identity, since the
    platform records who said it; the index it resolves against is ``LO_INDEX_PATH``, the same built
    snapshot every other reader here opens. Each round logs one INFO line and a failed round logs a
    WARNING naming the error class, so a silent process is a process that is not running rather than a
    healthy one with nothing to say. This worker neither reads nor writes a notification mode.
    """
    try:
        config = producer_config()
        if config is None:
            return 0
        allow_http = os.environ.get('LO_INTERNAL_ALLOW_HTTP') == '1'
        platform = JsonClient(os.environ['LO_PLATFORM_URL'], read_credential('LO_PRODUCER_TOKEN'),
                              allow_http=allow_http)
        index_path, source = os.environ['LO_INDEX_PATH'], os.environ[SOURCE_ENVIRONMENT]
        label(source)
        cursor = Path(config['cursor'])
        cursor.parent.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        log.warning('Config-drift producer cannot start; configuration is missing or invalid',
                    extra={'error_class': type(exc).__name__})
        return 1

    def deliver(item: dict[str, Any]) -> None:
        if platform.request('POST', '/v1/events', item)[0] != 200:
            raise TransportError('Drift intake refused; the cursor is not advanced')

    log.info('Config-drift producer started', extra={'artifacts': len(config['resources']),
                                                     'tick_seconds': config['interval_seconds']})
    with exclusive_owner(cursor):
        while True:
            try:
                summary = tick(index_path, config, cursor, deliver, now=dt.datetime.now(dt.timezone.utc),
                               source=source)
                log.info('Config-drift tick finished',
                         extra={'result': summary['result'], 'events': len(summary['events']),
                                'changed': summary['changed'], 'baselined': summary['baselined'],
                                'unreadable': summary['unreadable'],
                                'acknowledged': summary['acknowledged']})
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
                # sqlite3.Error because a round opens the inventory index, whose absence or damage
                # surfaces as an OperationalError, which is not an OSError: uncaught here it would end
                # the loop and let the service manager restart-loop on a missing mount.
                log.warning('Drift delivery unavailable; cursor not advanced, this round repeats',
                            extra={'error_class': type(exc).__name__})
                log.debug('Config-drift tick failed', exc_info=True)
            time.sleep(config['interval_seconds'])


if __name__ == '__main__':
    raise SystemExit(main())

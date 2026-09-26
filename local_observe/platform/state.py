"""Transactional incidents, action authority and leased notification delivery."""
from collections.abc import Callable, Iterator
from contextlib import contextmanager, closing
from dataclasses import dataclass
import datetime as dt
import json
from pathlib import Path
import re
import secrets
import sqlite3
from typing import Any
import uuid

from local_observe.inventory.validation import InvalidInventory, canonical, digest, timestamp, utc_text
from local_observe.log import get_logger
from local_observe import topology
from . import correlation

log = get_logger(__name__)

APPLICATION_ID = 0x4C4F5001
# The schema this build reads and writes. It must always name the highest key of MIGRATIONS below.
VERSION = 9

# The outcome class of one delivery attempt, spelled once. `pending` is an attempt still in flight;
# `accepted` is a receipt that repeated the delivery id; the other three are the only answers
# `finish_notification` may record for a failure. They are what lets an operator tell "the provider was
# unreachable" from "the provider refused" after the fact (ledger notifications). Nothing here stores a
# response body, a URL or a credential: the class is the whole diagnosis, and it is bounded by this
# tuple — a value outside it is a refusal, not a wider column.
ATTEMPT_CAUSES = ('pending', 'accepted', 'rejected', 'transport', 'policy')
# How long a notification callback token stays spendable, and the bounds it may be asked to change
# within. A callback is an intent and not a decision, so a short life costs nothing (ledger notifications).
CALLBACK_TTL_SECONDS = 3600
CALLBACK_TTL_BOUNDS = (60, 86400)
MIGRATE_COMMAND = 'lo-platform migrate'
MIGRATE_ACTOR = 'platform-migrate'
# SQLite header: bytes 18/19 are the WAL file-format versions, 24..27 the change counter and
# 92..95 the "version-valid-for" number that says the counter above is current (sqlite fileformat 2).
WAL_FORMAT = 2
HEADER_BYTES = 100
HEADER_MAGIC = b'SQLite format 3\x00'


class StateError(ValueError):
    pass


@dataclass(frozen=True)
class Actor:
    identity: str
    role: str


def require(actor: Actor, *roles: str) -> None:
    if not isinstance(actor, Actor) or actor.role not in roles or not actor.identity:
        raise StateError('Actor is not authorised for this operation')


def identifier(value: str) -> str:
    """Return `value` if it is a canonical UUID string, and refuse every other input the same way.

    `uuid.UUID` raises its own `ValueError` for text it cannot parse at all, which is a different
    exception from the refusal this function exists to raise — and `api.py` classifies anything that is
    not one of the platform's own sentences as a server-side 500. A caller sending `targets: ["later"]`
    was told "internal_error" about their own typo, so the parse failure is converted here rather than
    at the edge: every bad identifier now leaves this module as the one fixed sentence it always had.
    """
    try:
        parsed = str(uuid.UUID(value)) if isinstance(value, str) else None
    except ValueError:
        parsed = None
    if parsed != value:
        raise StateError('Expected canonical UUID')
    return value


def label(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,128}', value):
        raise StateError('Invalid bounded identifier')
    return value


def clock(now: dt.datetime | None = None) -> dt.datetime:
    return now or dt.datetime.now(dt.timezone.utc)


# The whole admitted `kind` vocabulary, spelled once. `anomaly` and `security` were added by event vocabulary
# ("start light, configurable to ramp up"); a kind outside this tuple is refused by
# `validate_event` rather than stored and rendered as something the operator has never seen.
EVENT_KINDS = ('availability', 'coverage', 'threshold', 'drift', 'anomaly', 'security')


SCHEMA = '''
CREATE TABLE events (id TEXT PRIMARY KEY, source TEXT NOT NULL, source_event_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL, received_at TEXT NOT NULL, payload TEXT NOT NULL, incident_id TEXT,
    UNIQUE(source,source_event_id));
CREATE TABLE conditions (key TEXT PRIMARY KEY, watermark TEXT NOT NULL, event_id TEXT NOT NULL,
    status TEXT NOT NULL, incident_id TEXT);
CREATE TABLE evidence (id TEXT PRIMARY KEY, source TEXT NOT NULL, payload TEXT NOT NULL,
    fingerprint TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE incidents (id TEXT PRIMARY KEY, condition_key TEXT NOT NULL, resource_id TEXT,
    status TEXT NOT NULL CHECK(status IN ('open','resolved')), opened_at TEXT NOT NULL,
    updated_at TEXT NOT NULL, last_event_id TEXT NOT NULL REFERENCES events(id));
CREATE INDEX incidents_condition ON incidents(condition_key,status);
CREATE TABLE outbox (sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
    incident_id TEXT NOT NULL REFERENCES incidents(id), payload TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','sending','sent','dead')), attempts INTEGER NOT NULL DEFAULT 0,
    available_at TEXT NOT NULL, lease_until TEXT, claim_token TEXT);
CREATE TABLE notification_attempts (id TEXT PRIMARY KEY, outbox_id TEXT NOT NULL REFERENCES outbox(id),
    started_at TEXT NOT NULL, finished_at TEXT, result TEXT NOT NULL, claim_token TEXT NOT NULL UNIQUE);
CREATE TABLE actions (id TEXT PRIMARY KEY, requester TEXT NOT NULL, retry_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL, decided_by TEXT, UNIQUE(requester,retry_key));
CREATE TABLE executions (id TEXT PRIMARY KEY, action_id TEXT NOT NULL UNIQUE REFERENCES actions(id),
    runner TEXT NOT NULL, token_hash TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL);
CREATE TABLE audit (sequence INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
    actor TEXT NOT NULL, operation TEXT NOT NULL, subject TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
'''

# Schema v2 (ledger control state): notification control state — mode, flood breaker, send budget, test
# windows, suppressions — stops being re-derived from the audit log on every claim and gets its own
# tables. The back-fill below is the ONLY code that reads audit for control; the audit rows keep
# being written exactly as before (they are the audit) and are read as history only by `Store.records()`
# (the capped newest-first window) and by `platform/audit_reader.py` (the bounded paged walk this build
# adds); neither read feeds a decision.
# The fallbacks are not conveniences: an unreadable `mode` becomes `off` and an unreadable `reason`
# still suppresses, both of which refuse a delivery; `channel`/`destination` become the empty string,
# which matches v1 exactly (a NULL there matched no budget query either) and can never equal a valid
# `label()`. `INSERT OR IGNORE` keeps the first of two suppressions of one delivery, because the fact
# that matters is that it may never be sent and the audit log still holds every claim of why.
CONTROL_SCHEMA = '''
CREATE TABLE notification_control (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE notification_reservations (id INTEGER PRIMARY KEY AUTOINCREMENT, outbox_id TEXT NOT NULL,
    channel TEXT NOT NULL, destination TEXT NOT NULL, test_window TEXT, at TEXT NOT NULL);
CREATE INDEX reservations_window ON notification_reservations(channel,destination,at);
CREATE TABLE notification_suppressions (outbox_id TEXT PRIMARY KEY, reason TEXT NOT NULL, at TEXT NOT NULL);
INSERT INTO notification_control(key,value,updated_at)
  SELECT 'mode', COALESCE(json_extract(detail,'$.mode'),'off'), at FROM audit
   WHERE operation='notification.mode' ORDER BY sequence DESC LIMIT 1;
INSERT INTO notification_control(key,value,updated_at)
  SELECT 'circuit:'||a.subject,
         json_object('at', a.at,
                     'reset_at', COALESCE((SELECT c.at FROM audit c WHERE c.subject=a.subject
                            AND c.operation='notification.circuit_reset' ORDER BY c.sequence DESC LIMIT 1),''),
                     'state', CASE WHEN a.operation='notification.circuit_open' THEN 'open' ELSE 'closed' END),
         a.at
    FROM audit a
   WHERE a.operation IN ('notification.circuit_open','notification.circuit_reset')
     AND a.sequence = (SELECT MAX(b.sequence) FROM audit b WHERE b.subject=a.subject
            AND b.operation IN ('notification.circuit_open','notification.circuit_reset'));
INSERT INTO notification_control(key,value,updated_at)
  SELECT 'test_window:'||a.subject, a.detail, a.at FROM audit a
   WHERE a.operation='notification.test_window'
     AND a.sequence = (SELECT MAX(b.sequence) FROM audit b WHERE b.subject=a.subject
            AND b.operation='notification.test_window');
INSERT INTO notification_reservations(outbox_id,channel,destination,test_window,at)
  SELECT a.subject, COALESCE(json_extract(a.detail,'$.channel'),''),
         COALESCE(json_extract(a.detail,'$.destination'),''),
         json_extract(a.detail,'$.test_window'), a.at
    FROM audit a WHERE a.operation='notification.reserved' ORDER BY a.sequence;
INSERT OR IGNORE INTO notification_suppressions(outbox_id,reason,at)
  SELECT a.subject, COALESCE(json_extract(a.detail,'$.reason'),'reason-not-recorded'), a.at
    FROM audit a WHERE a.operation='notification.suppressed' ORDER BY a.sequence;
'''

# Schema v3 (ledger notifications): the two facts the delivery rail was missing, added as columns and never as
# tables — `tests/test_state_migration.py` pins the table set this build creates, and a new table here
# would silently change what that pin claims. `outbox.channel` names which configured channel the row
# was routed to, so the per-channel budget and flood breaker the state model already carries reach a
# real delivery instead of existing only in the schema. `callback_token_hash`, `callback_expires_at`
# and `callback_consumed_at` hold the single-use inbound token: the secret itself is never stored, so
# a restored or copied database cannot hand back a spendable approval intent, and expiry is kept apart
# from consumption because an expired token and a spent one are different answers to give a channel.
# `notification_attempts.cause` is the outcome class above.
#
# Every statement is an `ALTER TABLE ... ADD COLUMN` with a DEFAULT, which SQLite answers by filling
# existing rows with that default, and the three `UPDATE`s below then say what each v2 attempt actually
# asserted. The defaults are chosen so a migrated row never asserts something v2 did not record:
# `channel` becomes the empty string, meaning "this row has not been routed by this build yet", because
# the channel a v2 send used is a fact about the operator's policy, not about the row — and the same
# fact already lives, back-filled at v2, in `notification_reservations.channel`. A row gets its channel
# written the moment this build claims it.
#
# The `UPDATE`s are not conveniences: `pending` would be a lie about a row that finished, and the only
# words the old boolean could mean are these — `accepted` is the receipt it recorded, `rejected` is "the
# provider did not accept this", and a claim whose lease expired or which never finished is precisely
# "no acknowledgement was obtained", which is `transport`. Nothing is rewritten into a cause this build
# did not witness, and no v2 row is deleted or invented.
DELIVERY_SCHEMA = '''
ALTER TABLE outbox ADD COLUMN channel TEXT NOT NULL DEFAULT '';
ALTER TABLE outbox ADD COLUMN callback_token_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE outbox ADD COLUMN callback_expires_at TEXT;
ALTER TABLE outbox ADD COLUMN callback_consumed_at TEXT;
ALTER TABLE notification_attempts ADD COLUMN cause TEXT NOT NULL DEFAULT 'pending';
UPDATE notification_attempts SET cause='accepted' WHERE result='accepted';
UPDATE notification_attempts SET cause='rejected' WHERE result='failed';
UPDATE notification_attempts SET cause='transport' WHERE result IN ('sending','unknown');
'''

# Schema v4  makes a post-action verification durable instead of leaving it
# as one four-field evidence row, where the threshold, the rule, the window and the *reason* were
# readable back only by someone who already knew them (`docs/units/verification.md`, "Evidence truth").
# Two new tables, and deliberately not one widened column on `actions`, `executions` or `incidents`: a
# verdict must never be able to overwrite the runner's own outcome, so the judgement lives beside the
# lifecycle rather than inside it. Neither table is back-filled — an action proposed before this
# migration has no binding, reads as `unbound`/`not-captured`, and inventing one from today's policy
# would be a numeric claim about a signal this build never witnessed.
#
# `verification_bindings` is keyed by the action, and that key *is* the rule "one proposal, one
# meaning": a retried action keeps the binding captured at its first proposal, and the UPDATE/DELETE
# triggers make re-binding after a policy change impossible at the file rather than merely unadvised in
# code. The CHECK is what keeps the two halves of that promise from describing one row together: a
# `bound` row carries a digested origin and the one reason `matched`, an `unbound` row carries one of
# the three captured refusal words and no origin. `not-captured` is un-storable on purpose — it means
# "no row exists", and a stored row saying it would let an explicit non-binding and an absent one mean
# different things on one table while reading back identically.
#
# `verification_records` is keyed by the logical verification id (a digest of execution, binding and
# normalised window), so "the same check again" is one row whatever producer asked, and a different
# window is a different row. The payload bound repeats in SQL what `verification_records.write_record`
# enforces before INSERT, so the 64 KiB the read surface promises is a property of the file and not of
# one caller's discipline; `verdict` is bounded to the three words while `reason` is not, because a
# stored CHECK on the reason list would answer a future taxonomy change as an `IntegrityError` (a 500)
# where the code answers it as a refusal. `recorded_by` is the identity that first wrote the statement,
# which a later identical replay by another authorised verifier never changes.
#
# `tests/test_state_migration.py` pins the exact table set this build creates, which is why v4 adds
# exactly these two tables and no third: the pin is the mechanism that makes "we only added what the
# contract named" checkable rather than a claim in a comment.
VERIFICATION_SCHEMA = '''
CREATE TABLE verification_bindings (action_id TEXT PRIMARY KEY REFERENCES actions(id),
    status TEXT NOT NULL CHECK(status IN ('bound','unbound')), reason TEXT NOT NULL,
    binding_id TEXT, origin TEXT, captured_at TEXT NOT NULL,
    CHECK(status='bound' AND reason='matched' AND binding_id IS NOT NULL AND origin IS NOT NULL
       OR status='unbound'
          AND reason IN ('unsupported-targets','origin-unmatched','origin-ambiguous')
          AND binding_id IS NULL AND origin IS NULL));
CREATE TRIGGER verification_bindings_no_update BEFORE UPDATE ON verification_bindings
    BEGIN SELECT RAISE(ABORT,'append-only verification binding'); END;
CREATE TRIGGER verification_bindings_no_delete BEFORE DELETE ON verification_bindings
    BEGIN SELECT RAISE(ABORT,'append-only verification binding'); END;
CREATE TABLE verification_records (verification_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES executions(id), fingerprint TEXT NOT NULL,
    payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB))<=65536),
    verdict TEXT NOT NULL CHECK(verdict IN ('cleared','not_cleared','unknown')), reason TEXT NOT NULL,
    recorded_by TEXT NOT NULL, recorded_at TEXT NOT NULL);
CREATE INDEX verification_records_execution ON verification_records(execution_id);
CREATE TRIGGER verification_records_no_update BEFORE UPDATE ON verification_records
    BEGIN SELECT RAISE(ABORT,'append-only verification record'); END;
CREATE TRIGGER verification_records_no_delete BEFORE DELETE ON verification_records
    BEGIN SELECT RAISE(ABORT,'append-only verification record'); END;
'''

# Schema v5  is ONE partial expression index over the control documents the v2 table already
# holds, and nothing else: no table, no column, no marker row, no archive, no deletion of history and no
# raised cap. Declared windows are never deleted, so the read that asked `key LIKE 'maintenance:%'` walked
# *every window ever declared* before it dropped the expired and revoked ones, and `MAX_WINDOW_ROWS`
# worth of old history silenced every future window while declarations kept succeeding. The index carries
# the end of an unrevoked window, so the read asks for the candidates it actually wants and a
# declaration's lifetime costs it nothing.
#
# The nested CASE is what keeps a malformed control document from being an error: `json_extract` raises on
# text that is not JSON, and SQLite does not promise to evaluate `json_valid` before an extract sitting
# beside it in one clause, so the guard is inside the same expression. A row failing either test indexes
# as NULL, is absent from the candidate set and stays what it was — history nobody can apply. A statement
# that could fail here would fail this migration and every later control write as well.
#
# What the index cannot give is authority: `platform/suppression._scan` re-checks the envelope, the
# declared block, the attestation and the expiry of every candidate it applies, because an index key is a
# search term and not a reason to silence a pager.
MAINTENANCE_WINDOW_END = ('CASE WHEN json_valid(value) THEN'
                          " CASE WHEN json_extract(value,'$.revoked') IS NULL"
                          " THEN json_extract(value,'$.declared.ends_at') END END")
#: The v5 index, named once so the `CREATE INDEX` and the read's `INDEXED BY` cannot drift apart.
MAINTENANCE_WINDOW_INDEX = 'maintenance_unrevoked_end'
#: The half-open range of declared-window keys — `MAINTENANCE_PREFIX` spelled in SQL (the two literals are
#: kept in step by `tests/test_maintenance_history.py`) — and the partial predicate of the index. A range
#: and not a `LIKE`, because a range is the form a partial index can be constrained by.
MAINTENANCE_WINDOW_KEYS = "key >= 'maintenance:' AND key < 'maintenance;'"
#: One candidate: a declared, unrevoked window whose stored end is after the instant being read. Both
#: sides are `utc_text` — fixed width, so these strings compare as the instants they name.
MAINTENANCE_WINDOW_LIVE = f'({MAINTENANCE_WINDOW_END}) > ?'
MAINTENANCE_WINDOW_SCHEMA = (f'CREATE INDEX {MAINTENANCE_WINDOW_INDEX} ON notification_control'
                             f' ({MAINTENANCE_WINDOW_END}, key) WHERE {MAINTENANCE_WINDOW_KEYS};\n')

# Why a window is a control key and not a table — the reasoning suppression recorded, which the suppression index did
# not
# change (port table §6 `aiops/dedup`). A planned
# maintenance window stops being prose in a detector file and becomes control state — a human actor's
# declaration that "findings about this resource or this rule are expected for this bounded period, so do
# not page for them" — and that state is stored under `maintenance:<id>` in the v2 `notification_control`
# table (`maintenance_key` below), beside the delivery mode, the flood breakers and the approved test
# windows whose shape it copies key-for-key.
#
# A typed table was tried first and is the shape the same promise wants: a window silences a pager, so
# "it has an end, and that end is at most `platform/suppression.MAX_WINDOW_SECONDS` after its start" reads
# better as a CHECK in the file than as a rule in one module. What it would cost is a *table*, and the
# files below exist to make that cost visible: `tests/test_state_migration.py` pins the exact table set
# this build creates, and `tests/test_maintenance_windows.py` asserts that same pin through the import it
# takes from that file. `tests/test_control_state_migration.py` carves a v1 file out of `MIGRATIONS[1]`
# alone and so is not moved by a new table at all — which correlation proved by adding one, and it counted more
# than it expected: `incident_members` moved the two pins named above, left that carve-out assertion
# untouched, and moved three further files that a later card will want named here rather than rediscovered —
# `tests/test_maintenance_history.py` (a fresh file's table set compared against a v4-pinned one),
# `tests/test_verification_records_migration.py` (that comparison twice, under the sentence "exactly two
# tables joined the schema", which was only ever true while nothing after v4 added one) and
# `tests/test_escalation_history.py` (which rewinds `user_version` to the step below the escalation indexes
# and assumes that step is still the newest, so any step above it re-applies and aborts). Each needs one
# line and none of them is about grouping. It was not what the suppression index
# needed either: the defect was the read's bound, and an index over the existing documents removes it
# without moving a table pin at all. The typed table stays a card of its own.
#
# What giving up the table gives up is a CHECK, so the bound is enforced twice elsewhere instead:
# `platform/suppression.py` refuses it at declaration *and* at every use, and every window this build
# applies is **attested** — the control row carries the `audit` sequence of the `maintenance.declared`
# row that created it, and the read re-checks that row's subject and detail against the stored document.
# `audit` has the append-only UPDATE and DELETE triggers `notification_control` does not, so a restored,
# copied or hand-edited file cannot hold a window that no human declared: the declaration is what makes
# the row real, it is checked per use, and it costs one primary-key lookup. Anything that fails either
# check is never applied, which pages — the loud direction for a suppression mechanism.

# Schema v6 : three indexes, and nothing else — no table, no column, no back-fill, no row
# rewritten. `platform/escalation.py` used to decide from `Store.records`, the capped newest-first
# window, so a platform whose lifetime history passed 100 rows stopped escalating forever (the window was
# full of unrelated history) and closed tracked incidents that had merely aged out of it. The replacement
# reads the authoritative tables, and three of its lookups are only safe if they are indexed: an
# unindexed one is a scan of a table that grows without bound, on a path that runs every tick.
#
# * `incidents(status)` — the discovery page (`status='open' AND rowid>cursor ORDER BY rowid LIMIT n`).
#   Inside one status value the index entries are already in rowid order, so paging seeks and resumes
#   instead of sorting, and a million `resolved` rows cost nothing.
# * `actions(<incident id expression>, status, id)` — an expression index over the field the approval
#   fingerprint already covers, proving a human decision regardless of the action's age. `id` is carried
#   so the approval-intent join is answered from the index alone.
#   The `CASE WHEN json_valid(payload)` guard is not a convenience: an index over a bare
#   `json_extract(payload,'$.incident_id')` cannot be built at all over one historical row whose payload
#   is not JSON (`json_extract` raises on it), and a migration that fails on the row it cannot parse is a
#   migration that cannot be applied. The guard turns such a row into NULL, which never equals a UUID, so
#   a malformed action is simply not ack evidence — the same conclusion the code already drew about it.
# * `audit(subject) WHERE operation='action.approval_intent'` — a *partial* index, because `audit` is
#   append-only and unbounded while this question is about one operation. It is the only index this
#   platform has ever put on `audit`; every other read of it is the bounded walk in
#   `platform/audit_reader.py`.
#
# None of the three is ever created at runtime. `platform/escalation_reader.py` names them with
# `INDEXED BY`, which is a refusal and not a hint: a file missing one answers "no query solution", and
# the scheduler holds the affected work rather than falling back to a scan. The names and the actions
# expression are therefore shared vocabulary — spelled once here, imported by the reader, because an
# expression index is matched *structurally* and a paraphrase on the read side is a broken read.
#
# This step follows the maintenance-candidate index in v5. Both preserve business rows.
ESCALATION_INCIDENTS_INDEX = 'escalation_incidents_status'
ESCALATION_ACTIONS_INDEX = 'escalation_actions_incident'
ESCALATION_AUDIT_INDEX = 'escalation_audit_intent'
#: The one spelling of "which incident does this action belong to": the expression the index is built on
#: and the expression the acknowledgement read filters by. They must be the same text.
ESCALATION_ACTIONS_EXPRESSION = ("CASE WHEN json_valid(payload) THEN json_extract(payload,"
                                 "'$.incident_id') END")
#: The single audit operation acknowledgement evidence takes, and the predicate the partial index is cut
#: on. `Store.record_callback` is its only author.
ESCALATION_INTENT_OPERATION = 'action.approval_intent'

ESCALATION_INDEX_SCHEMA = f'''
CREATE INDEX {ESCALATION_INCIDENTS_INDEX} ON incidents(status);
CREATE INDEX {ESCALATION_ACTIONS_INDEX} ON actions({ESCALATION_ACTIONS_EXPRESSION}, status, id);
CREATE INDEX {ESCALATION_AUDIT_INDEX} ON audit(subject) WHERE operation='{ESCALATION_INTENT_OPERATION}';
'''

# Schema v7 (correlation, port table §6 `aiops/correlate`): one table that did not exist, the one index a new
# read needs, and no column added to any business row. What the table holds is the answer to "why is
# this condition in this incident?", which is the claim the product is positioned on (positioning) and the one
# thing an incident row could not say before: `conditions.incident_id` already points many conditions at
# one incident — that
# many-to-one pointer is why no column on `incidents` was needed — but *that* is a fact with no
# explanation, and §4 promises the minimum redacted context to understand an action after the source data
# expires under its per-signal retention policy. An explanation that lived in a query over telemetry would
# be unreadable on the day someone asks why an approval was granted.
#
# `incident_members` is therefore one row per grouping link, keyed by the pair it explains, and the row is
# the durable half of `platform/correlation.py`'s judgement: `rationale` is the canonical JSON array of
# matched signals (kind, one bounded sentence, a 0..1 score, and the *references* that corroborate it —
# declared path as resource UUIDs and relation words, plus the digest of the declaration they came from),
# never an event payload, never an evidence parameter, never a value copied out of a producer. The width
# CHECK is `correlation.MAX_RATIONALE_CHARS` spelled from the same constant the module enforces before it
# returns a link, so the bound belongs to the file and not to one caller's discipline — the v4
# verification-payload precedent, where the read surface's promise and the column's CHECK are one number.
#
# No row is written for the condition that *opened* an incident: an incident is its own anchor, and
# `incidents.condition_key` says so. A row's `at` is when the link was made, not the event's instant.
# Nothing here is append-only by trigger: `rca` re-points members between incidents when a merge settles,
# and UPDATE/DELETE triggers on this table would answer that card with an abort instead of a re-point. The
# foreign key stays, which is what makes a merge re-point its members before it can drop an empty
# incident — the loud order, not a quiet orphan.
#
# The one index is for a read this migration creates, on a table that grows for the life of the file:
# `conditions(incident_id)` serves "is this the last open member of the group?" on every
# resolution and the view's one-read-per-page member query, and it did not exist before because nothing
# ever asked the question in that direction. **No index is created on `incident_members`**: its primary key
# is `(incident_id, condition_key)`, whose autoindex already answers every read this table has (verified by
# `EXPLAIN QUERY PLAN` in `tests/test_incident_grouping_migration.py`, which asserts the read uses an index
# *and* that this migration created exactly one), and a second index over the same leading column is write
# cost and space for nothing. `presentation.grouping_info` does not pin it with `INDEXED BY` for that
# reason: naming `sqlite_autoindex_*` would tie a read to how SQLite implements a constraint, and the
# explicit-index refusal `escalation_reader`/`maintenance_reader` need exists to protect a *guarded*
# fallback, which a primary key cannot drift away from.
#
# Scope of that sentence, since schema v9: "every read this table has" was true of the reads step 7
# created. `suppression._absorbed_openings` later asked it by `condition_key` — the other end of the key
# — and `MIGRATIONS[9]` below adds that one index. What step 7 created is unchanged: one table, and no
# index inside that step.
GROUPING_TABLE = 'incident_members'
#: Characters one stored rationale may hold — `correlation.MAX_RATIONALE_CHARS`, written into the CHECK so
#: the promise is a property of the file. Repeated once here as the schema's own number.
GROUPING_RATIONALE_LIMIT = correlation.MAX_RATIONALE_CHARS
GROUPING_SCHEMA = f'''
CREATE TABLE {GROUPING_TABLE} (incident_id TEXT NOT NULL REFERENCES incidents(id),
    condition_key TEXT NOT NULL, rationale TEXT NOT NULL, at TEXT NOT NULL,
    CHECK(length(rationale) BETWEEN 1 AND {GROUPING_RATIONALE_LIMIT}),
    PRIMARY KEY (incident_id, condition_key));
CREATE INDEX conditions_incident ON conditions(incident_id);
'''

#: How many open incidents one admission may look at before it stops looking. A cut search groups nothing
#: — it files the event's own incident, which costs an operator a second page and never costs them a
#: wrong answer — and 50 is the point where the read stops being a lookup on a platform whose open
#: incidents are the ones a human has not closed.
GROUP_CANDIDATES = 50

# One candidate group: the open incident, the rule that is its subject and that subject's stored event.
# `incidents.last_event_id` is the read `platform/suppression._firing_resources` already makes, so a
# grouped incident keeps describing the condition that *opened* it; a join deliberately never moves that
# pointer (see `Store._join_group`), which is what keeps escalation's base verdict and dependency
# suppression's blame reading the cause rather than whichever symptom arrived last. The rule id is read
# because an escalation rung's incident is exempt from grouping, and a rung is only identifiable by the
# rule its event was filed under.
GROUP_CANDIDATE_SQL = ("SELECT i.id AS incident_id, json_extract(e.payload,'$.rule_id') AS rule_id,"
                       ' e.payload AS payload FROM incidents i JOIN events e ON e.id=i.last_event_id'
                       " WHERE i.status='open' AND i.id<>? ORDER BY i.rowid LIMIT ?")

#: The one audit operation a grouping link takes, named here so a test, a reader of `audit` and the
#: writer cannot disagree about its spelling. The actor on the row is the producer whose event caused the
#: link — `intake` has audited that same identity against that same event one statement earlier, in this
#: same transaction — so the two rows read as one decision by one writer.
GROUPING_OPERATION = 'incident.grouped'

# Schema v8 : one index over one column that already
# exists, and nothing else — no table, no column, no back-fill, no row rewritten, no business value moved.
# What it indexes is `events.incident_id`, the membership pointer `Store.intake` writes and
# `Store._join_group` moves, and it exists for exactly one read: the RCA component's `MEMBER_SQL`, which
# asks "which events belong to this incident?" once per incident per RCA round. Nothing else in the
# product asks that question of `events` — `presentation.grouping_info` walks incident → condition →
# event and `escalation_reader` walks incident → action — so this is one component's read cost, named in
# the schema rather than tidied into a general "index the obvious columns" step. That read is named in
# prose and never by its dotted module path: `tests/test_rca_component.py` asserts this file never names
# the RCA module at all, which is the checkable form of "the delivery rail does not depend on RCA".
#
# Why the read's own bound was not sufficient, and why it stays: its `MEMBER_READ_INSTRUCTIONS` (128 000
# SQLite instructions) is what lets a short member channel say "membership is unknown" instead of "this
# incident has no members", which is an honesty bound and is not replaced here. It was never a *cost*
# bound. Unindexed, the plan for that statement is `SCAN events`: SQLite walks the whole table — every
# event of every incident, and every `payload` document it passes over — to gather the `LIMIT` rows that
# name one incident, so the work done scales with the file's lifetime while the answer stays the size of
# one incident. On a platform that has filed events for the life of the file, the budget bought a
# guaranteed, budget-spending failure per incident rather than a cheap answer; the index makes the work
# proportional to the incident, and the ceiling that then actually binds is that read's `MAX_MEMBER_ROWS`.
#
# This index is deliberately **not** named with `INDEXED BY` on the read side, which is the opposite of
# `escalation_reader`/`maintenance_reader` and is a decision, not an omission. Those two guard a fallback
# that would silently degrade into a scan on a path that pages on a timer; the member read already
# has its guard — the instruction budget and the gap sentence it writes — and `INDEXED BY` would replace
# that honest gap with an SQLite error whose wording the read cannot distinguish from "the database could
# not be opened", which is the one thing the member channel must never over-report. A restored pre-v8
# file therefore still answers "membership is unknown, not absent" and is fixed by `lo-platform migrate`.
#
# The checklist the v7 preamble promised a new step must answer, and what this one moved: a step with no
# table does **not** move `tests/test_state_migration.py`'s `CURRENT_TABLES` (it pins tables, not
# indexes); `tests/test_incident_grouping_migration.py` asserted that step 7 created exactly one index by
# migrating a v6 file to `VERSION`, which is now two steps, so that migration runs as the v7 build and a
# new test covers v7 → v8 and asserts `EXPLAIN QUERY PLAN` for `MEMBER_SQL` names `events_incident`;
# `tests/test_escalation_history.py` rewinds `MIGRATIONS` to steps 1..6 and is unmoved because the newest
# step it can reach is still the one its indexes live in; `tests/test_upgrade_acceptance.py` reads
# `state.VERSION` and is unmoved; `tests/test_maintenance_history.py` and
# `tests/test_verification_records_migration.py` compare a fresh file against a migrated one and both
# pass unchanged (they compare tables and rows, and this step adds neither); and the two documents that
# state the schema number — `docs/CONTRACTS.md` §5's first sentence and the migration paragraph of
# `local_observe/platform/README.md` — move with it, as does the comment in the RCA module that said no
# index exists.
EVENTS_INCIDENT_INDEX = 'events_incident'
MEMBER_INDEX_SCHEMA = f'''
CREATE INDEX {EVENTS_INCIDENT_INDEX} ON events(incident_id);
'''

# Schema v9 : one index over one column that has existed
# since the table itself, and nothing else — no table, no column, no back-fill, no row rewritten, no
# business value moved. What it indexes is `incident_members.condition_key`, the far end of that table's
# `(incident_id, condition_key)` primary key, and it exists for exactly one read:
# `suppression._absorbed_openings`, which asks "how many openings did a group swallow for *this*
# condition?" inside the flap count, once per page a booking round puts in the outbox. The reads step 7
# wrote come from the incident side and are served by the primary key's autoindex; this one comes from
# the condition side, which no constraint of that table leads with. Like v8 this is one component's read
# cost named in the schema, not a general "index the obvious columns" step: every other read of this table
# in the product is keyed by incident (`presentation.grouping_info`'s two statements are the only ones
# that name it outside `suppression`), and the primary key already serves those.
#
# Why it is a schema step and not a bound: the read is already capped at `MAX_TRANSITION_ROWS`, but that
# cap bounds the *answer*, never the work. Unindexed, the plan is `SCAN incident_members` — SQLite walks
# every link the file has ever recorded, and every `rationale` document it passes over, to count the few
# that name one condition. Measured on 2026-09-10 before the index existed: 0.1 ms with 500 links stored,
# 2.2 ms with 10 000, 9.3 ms with 50 000 (worst case: a condition with no link row, so the scan runs to
# the end of the table). That is a per-page cost multiplied by the life of the file, on the one path that
# also holds the writer's lock; the index makes the work proportional to the condition.
#
# This index is deliberately **not** named with `INDEXED BY` on the read side, for the same reason v8
# refused it: the count has an honest zero to give (`_grouping_present` answers "no link table yet" with
# zero absorbed openings, which is the floor this count is allowed to report), and an SQLite error for a
# missing index is indistinguishable from a database that cannot be opened — which would turn a
# bookable flap decision into a failed admission. A pre-v9 file therefore still answers the question, with
# the scan it always paid, and is fixed by `lo-platform migrate`.
#
# The checklist the v7 preamble promised a new step must answer, and what this one moved: a step with no
# table does **not** move `tests/test_state_migration.py`'s `CURRENT_TABLES` (it pins tables, not indexes)
# and nothing in that file names the newest version, so it is unmoved; step 7's and step 8's cases in
# `tests/test_incident_grouping_migration.py` now run rewound to their own build — both assert "this step
# created exactly one index", which a migration that ran past its own step would answer with two — and a
# new test covers v8 → v9 and asserts `EXPLAIN QUERY PLAN` for the absorbed-openings statement names
# `incident_members_condition`; that file's v1 whole-chain test gained one step name; `tests/test_escalation_history.py`
# rewinds `MIGRATIONS` to steps 1..6 and is unmoved because the newest step it can reach is still the one
# its indexes live in; `tests/test_upgrade_acceptance.py` reads `state.VERSION` and is unmoved (its index
# list names the four escalation/maintenance indexes, not this one); and the two documents that state the
# schema number — `docs/CONTRACTS.md` §5's first sentence and the migration paragraph of
# `local_observe/platform/README.md` — move with it, as do the two places that quoted the scan figures as
# remaining debt (`suppression._count_transitions` and the correlation row of `DEPENDENCIES.md`).
MEMBERS_CONDITION_INDEX = 'incident_members_condition'
MEMBERS_CONDITION_INDEX_SCHEMA = f'''
CREATE INDEX {MEMBERS_CONDITION_INDEX} ON {GROUPING_TABLE}(condition_key);
'''

# target version -> the whole script that reaches it from the version below. MIGRATIONS[1] is the
# original schema, so a fresh database and a migrated one end up built by the same text, and a fresh
# database reaches v9 the same way an operational one does: by applying every script above, in order —
# which is why the v5 step builds its index from `MIGRATIONS[2]`'s table and not from a special case.
MIGRATIONS: dict[int, str] = {1: SCHEMA, 2: CONTROL_SCHEMA, 3: DELIVERY_SCHEMA,
                              4: VERIFICATION_SCHEMA, 5: MAINTENANCE_WINDOW_SCHEMA, 6: ESCALATION_INDEX_SCHEMA,
                              7: GROUPING_SCHEMA, 8: MEMBER_INDEX_SCHEMA, 9: MEMBERS_CONDITION_INDEX_SCHEMA}

# The one key that is not prefixed: which delivery mode the service last recorded for itself.
CONTROL_MODE = 'mode'


def circuit_key(channel: str) -> str:
    """Return the control key holding the flood breaker of one notification channel."""
    return 'circuit:' + channel


def test_window_key(window_id: str) -> str:
    """Return the control key holding the immutable definition of one approved test window."""
    return 'test_window:' + window_id


#: The prefix under which declared maintenance windows live in `notification_control` (suppression). One key
#: per window, holding one small JSON document — the same shape `test_window:` uses for an approved test
#: window's definition, and the same reason: it is written by an authorised actor, read on the delivery
#: path, and never counted the way a send slot is. Why this is a key and not a table of its own is above
#: `MIGRATIONS`.
MAINTENANCE_PREFIX = 'maintenance:'


def maintenance_key(window_id: str) -> str:
    """Return the control key holding one declared maintenance window.

    The id is validated by `platform/suppression.declare_window`, which is where a human's declaration is
    checked; this function only spells the key, so it stays usable on a read path that is walking keys it
    did not write.
    """
    return MAINTENANCE_PREFIX + window_id


def control_read(connection: sqlite3.Connection, key: str) -> str | None:
    """Return the value stored under one notification control key, or None when it was never written."""
    row = connection.execute('SELECT value FROM notification_control WHERE key=?', (key,)).fetchone()
    return row[0] if row else None


def control_write(connection: sqlite3.Connection, key: str, value: str, now: dt.datetime) -> None:
    """Replace one notification control key with its new value and the instant it changed."""
    connection.execute('INSERT INTO notification_control(key,value,updated_at) VALUES (?,?,?) '
                       'ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at',
                       (key, value, utc_text(now)))


def control_declare(connection: sqlite3.Connection, key: str, value: str, now: dt.datetime) -> int:
    """File one *new* control key, and report whether the key was free.

    `control_write` above replaces a value, because the delivery mode and a flood breaker are states that
    move. A maintenance window is a *declaration*, and a declaration that quietly overwrote the one
    already under its key would move a pager's silence — selector, times, reason, author — with nothing
    but a refused attempt's audit row to show for it. So this inserts and never updates: 0 means
    "something already lives under this key", and the caller answers with what is stored rather than with
    a fresh claim about who declared what.
    """
    return connection.execute('INSERT OR IGNORE INTO notification_control(key,value,updated_at)'
                              ' VALUES (?,?,?)', (key, value, utc_text(now))).rowcount


def record_reservation(connection: sqlite3.Connection, outbox_id: str, detail: dict[str, Any],
                       now: dt.datetime) -> None:
    """Take one send slot in the durable budget table; `detail` is the same route the audit row carries."""
    connection.execute('INSERT INTO notification_reservations(outbox_id,channel,destination,test_window,at) '
                       'VALUES (?,?,?,?,?)',
                       (outbox_id, detail['channel'], detail['destination'], detail['test_window'], utc_text(now)))


def record_suppression(connection: sqlite3.Connection, outbox_id: str, reason: str, now: dt.datetime) -> None:
    """Mark one delivery as never sendable, beside the audit row that records the same reason."""
    connection.execute('INSERT OR IGNORE INTO notification_suppressions(outbox_id,reason,at) VALUES (?,?,?)',
                       (outbox_id, reason, utc_text(now)))


def notification_id(event_id: str) -> str:
    """Return the outbox id the delivery booked by one event carries — the one definition of that mint.

    Derived from the event id alone, so a caller holding the event (`platform/suppression`, folding the
    send its own admission booked) can name the row by primary key instead of searching for it. Two
    copies of this formula would be two identities for one delivery, which is the failure
    `suppression.condition_key` is written to avoid rather than repeat.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_URL, event_id + ':notification'))


class Store:
    """One durable, single-writer platform database, opened only at a version this build understands."""

    def __init__(self, path, notification_policy=None, *, channel_policies=None,
                 verification_policy=None, migrate: bool = False,
                 refusal_clock: Callable[[], float] | None = None) -> None:
        """Open `path` at `VERSION`, creating it empty, or migrating it forward when asked to.

        `migrate=True` is the only way an existing database is ever changed by opening it, and it
        copies the file first; without it an older database is refused with the command to run.

        The refusal audit budget (`record_refusal`) is created here and belongs to this object, which
        means to this process: its counters and its token bucket do not survive a restart and are
        never read from the database. `refusal_clock` replaces the bucket's monotonic time source and
        exists for tests only — production passes nothing and gets `time.monotonic`.

        Args:
            path: Where the operational database lives.
            notification_policy: The policy of the store's own (primary) channel; the default is the
                recording policy, which sends nothing anywhere.
            channel_policies: Optional ``{channel: NotificationPolicy}`` for the *other* configured
                channels, in the operator's preference order. Routing tries the primary channel first
                and then these in order, so the set is a failover list rather than a fan-out. The
                primary is always first whatever this dict's order says, and the store's own policy is
                authoritative for its own channel name.
            verification_policy: The reviewed verifier/detector policy for verification records, or
                `None` (the default) to keep this build off: no binding is captured at proposal, no
                verification record is written, and proposals do not query the new tables. A policy is read
                from the service file an operator mounts — this slice ships no loader, so nothing here
                opens a path or reads an environment value; a later API startup does that and hands the
                validated object over.
            migrate: Apply the missing migrations to an existing database.

        Raises:
            StateError: A policy is filed under a channel name that is not its own, a verification
                policy is neither `None` nor a `VerificationPolicy`, or the database is of a version
                this build refuses to open.
        """
        from .verification_records import VerificationPolicy
        # First, and before anything looks at the file: a bad policy is a refusal about the caller's
        # configuration, and a store that created or opened a database before noticing had already done
        # the one thing this constructor exists not to do on a bad argument. A plain dict is refused
        # rather than accepted: `VerificationPolicy` is where every bound is decided, and an implicit
        # construction here would be a second, unreviewed copy of those rules on the widest-used path.
        if verification_policy is not None and not isinstance(verification_policy, VerificationPolicy):
            raise StateError('Verification policy must be a VerificationPolicy or None')
        self.verification_policy = verification_policy
        from .notification_safety import NotificationPolicy
        self.notification_policy = notification_policy or NotificationPolicy()
        # Primary first, then the declared order: a dict's order is the operator's preference, and this
        # is the one place that order is fixed so `reserve_route` and the docs cannot disagree.
        channels: dict[str, Any] = {self.notification_policy.channel: self.notification_policy}
        for name, extra in (channel_policies or {}).items():
            if name == self.notification_policy.channel:
                continue  # the policy this store was handed is the one its own channel runs on
            label(name)
            if getattr(extra, 'channel', None) != name or not hasattr(extra, 'max_attempts'):
                raise StateError('Channel policy is filed under the wrong channel name')
            channels[name] = extra
        self.channel_policies: dict[str, Any] = channels
        from .refusals import RefusalAudit
        self._refusal_audit = RefusalAudit(clock=refusal_clock)
        self.path = Path(path)
        if self.path.is_symlink():
            raise StateError('Refusing symlink state database')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # What this call did to the file, so `lo-platform migrate` can report it without reopening.
        self.migrated_from: int | None = None
        self.migration_backup: Path | None = None
        self._check_build()
        current = self._open_version()
        if current is None:
            self._create()
        elif current < VERSION:
            self._migrate(current, migrate)

    def add_channels(self, channel_policies: dict[str, Any] | None) -> None:
        """Register the extra channels this process can send on, after the primary one.

        Split out of the constructor because the set of channels belongs to the serving process: the
        channels document is read only when the mode can send (recording and off must not open a channel
        credential), and a store built without it must keep routing on its primary channel alone. Call
        it before the first claim: a claim already in flight booked its slot against the set as it
        stood, and re-routing it afterwards would make that row's history lie.

        Args:
            channel_policies: ``{channel: NotificationPolicy}`` in preference order. The store's own
                channel is always tried first whatever this mapping's order says.

        Raises:
            StateError: A policy is filed under a name that is not its own, or one channel is
                registered twice with two different budgets.
        """
        for name, extra in (channel_policies or {}).items():
            label(name)
            if getattr(extra, 'channel', None) != name or not hasattr(extra, 'max_attempts'):
                raise StateError('Channel policy is filed under the wrong channel name')
            known = self.channel_policies.get(name)
            if known is not None and known != extra:
                raise StateError('Notification channel is registered with two budgets')
            self.channel_policies[name] = extra

    @staticmethod
    def _check_build() -> None:
        """Refuse to touch any file at all while VERSION and the migration table disagree."""
        targets = sorted(MIGRATIONS)
        if not targets or targets[0] != 1 or targets[-1] != VERSION:
            raise StateError(f'Build error: schema VERSION {VERSION} does not match migrations {targets}')

    def _connect(self) -> sqlite3.Connection:
        """Return a connection carrying the pragmas this database is designed around."""
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('PRAGMA synchronous=FULL')
        return connection

    def _open_version(self) -> int | None:
        """Return the platform `user_version` on disk, or `None` when this build may create the file.

        Everything else is refused as it always was: a file owned by another application (any other
        `application_id` with content in it), and a platform database this build cannot describe — one
        newer than `VERSION`, or a `user_version` of 0 that is half-created at best.
        """
        self._refuse_orphaned_wal()
        # Inspect with a bare connection: the WAL/synchronous pragmas in _connect() write to the file
        # header, and a database this build is about to refuse must be left byte-for-byte as found.
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            app = connection.execute('PRAGMA application_id').fetchone()[0]
            version = connection.execute('PRAGMA user_version').fetchone()[0]
            tables = connection.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
            migratable = app == APPLICATION_ID and 0 < version < VERSION
            if (app, version) != (APPLICATION_ID, VERSION) and (app, version, tables) != (0, 0, 0) and not migratable:
                raise StateError('Unsupported operational database; restore or migrate explicitly')
            return version if app else None

    def _refuse_orphaned_wal(self) -> None:
        """Fail closed on a database whose own header says its `-wal` sidecar is still needed.

        Bytes 92..95 that do not match the change counter mean the file's header does not claim to be
        complete on its own: the pages that would finish it live only in the `-wal`. Opening that
        file alone reports an intact but older platform, which is the copy CONTRACTS §7 forbids. A
        complete file (the usual case: SQLite checkpoints and deletes the sidecar when the last
        connection closes) has matching numbers and is opened unchanged.
        """
        if not self.path.is_file():
            return
        with self.path.open('rb') as handle:
            header = handle.read(HEADER_BYTES)
        if len(header) != HEADER_BYTES or header[:len(HEADER_MAGIC)] != HEADER_MAGIC:
            return
        if header[18] != WAL_FORMAT or header[19] != WAL_FORMAT:
            return
        if int.from_bytes(header[24:28], 'big') == int.from_bytes(header[92:96], 'big'):
            return
        sidecar = self.path.with_name(self.path.name + '-wal')
        if sidecar.is_file() and sidecar.stat().st_size:
            return
        raise StateError('Operational database is incomplete without its -wal sidecar; restore a backup'
                         ' or recover the sidecar, and copy a running database with backup, never cp')

    def _create(self) -> None:
        """Build an empty database by applying every migration in one transaction; creation audits nothing."""
        script = ''.join(MIGRATIONS[target] for target in sorted(MIGRATIONS))
        with closing(self._connect()) as connection:
            connection.executescript('BEGIN IMMEDIATE;\n' + script +
                f'PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version={VERSION}; COMMIT;')

    def _migrate(self, current: int, enabled: bool) -> None:
        """Copy the database, then apply each missing migration, one audited transaction per step.

        Opening a store never silently rewrites state: without `enabled` this raises the command an
        operator must run instead. Each step ends with its own `PRAGMA user_version` inside the same
        `BEGIN IMMEDIATE`, and that pragma is transactional, so a crash between steps leaves the
        last committed version — an older but consistent database the next run continues from — and
        never a half-created table.
        """
        if not enabled:
            raise StateError(f'Operational database is version {current}; run {MIGRATE_COMMAND}')
        targets = list(range(current + 1, VERSION + 1))
        gaps = [target for target in targets if target not in MIGRATIONS]
        if gaps:
            raise StateError(f'No migration from version {current} to {VERSION}: step {gaps} is absent')
        self.migration_backup = self._snapshot(current)
        self.migrated_from = current
        for target in targets:
            with closing(self._connect()) as connection:
                try:
                    connection.executescript('BEGIN IMMEDIATE;\n' + MIGRATIONS[target] +
                        self._audit_migration(connection, current, target) +
                        f'PRAGMA user_version={target}; COMMIT;')
                except sqlite3.Error as exc:
                    # Closing the connection discards the failed step, so the file stays readable.
                    raise StateError(f'Migration to version {target} failed; the database stays at '
                                     f'version {target - 1} and the verified copy is {self.migration_backup}') from exc

    def _snapshot(self, current: int) -> Path:
        """Copy the file about to be migrated and integrity-check the copy before it is used again.

        CONTRACTS §7: "Snapshot before a schema change; a digest rollback is not a data rollback."
        The name carries the version the copy holds and the UTC time it was taken; `backup()` opens
        the destination exclusively, so a rerun can never replace the only recovery copy.
        """
        stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        destination = self.path.with_name(f'{self.path.name}.pre-v{current}-{stamp}.db')
        self.backup(destination)
        return destination

    @staticmethod
    def _audit_migration(connection: sqlite3.Connection, source: int, target: int) -> str:
        """Return the audit row for one step as SQL text, quoted by SQLite itself.

        The row has to commit with its migration or not at all, and `executescript` accepts no
        parameters, so `quote()` builds the literals; every value is chosen by this module.
        """
        detail = canonical({'from': source, 'to': target, 'script_sha256': digest(MIGRATIONS[target])})
        values = [connection.execute('SELECT quote(?)', (value,)).fetchone()[0] for value in
                  (utc_text(dt.datetime.now(dt.timezone.utc)), MIGRATE_ACTOR, 'schema.migrated', str(target), detail)]
        return 'INSERT INTO audit(at,actor,operation,subject,detail) VALUES ({},{},{},{},{});\n'.format(*values)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('BEGIN IMMEDIATE')
            with connection:
                yield connection

    @staticmethod
    def audit(connection: sqlite3.Connection, now: dt.datetime, actor: str, operation: str, subject: str,
              detail: Any = None) -> None:
        connection.execute('INSERT INTO audit(at,actor,operation,subject,detail) VALUES (?,?,?,?,?)',
                           (utc_text(now), actor, operation, subject, canonical(detail or {})))

    @contextmanager
    def refusal(self, attempt: str, actor: Any, subject: Any = None, *,
                now: dt.datetime | None = None) -> Iterator[None]:
        """Refuse an action attempt, and audit the refusal **after** the refused transaction is gone.

        Usage is one nesting decision, not a convention: each of the four audited lifecycle methods
        opens with `with self.refusal(<attempt>, actor, <subject>, now=now):` and its whole body —
        including the role gate, the validations and the injected policy call that run *before* any
        `transaction()` — sits inside it.

        Why the nesting is the design. `transaction()` is `closing(connect())` around `with connection:`
        (`state.py`), so when the body raises, that transaction is rolled back and its connection is
        closed *on the way out of the inner `with`* — before the exception reaches this `except`. The
        audit write is therefore never inside the aborted transaction (nothing can erase it afterwards)
        and can never commit the refused partial state (it is already discarded). An AST test in
        `tests/test_refusal_audit.py` pins the shape rather than trusting the comment, because the
        property dies the moment someone moves a `transaction()` call out of the wrapper.

        Only the platform's own two refusal classes are caught. Anything else — a `KeyError` from a
        broken action-definition table, a driver error — is not a denial and stays exactly what it is
        today: an unhandled 500, logged as one. The original exception is re-raised unchanged, so the
        sentence, the `stable_code` the API derives from it and the HTTP status are untouched.

        Raises:
            StateError: The wrapped body raised it, unchanged. A failed audit write never replaces it.
        """
        from .refusals import reason_for
        try:
            yield
        except (StateError, InvalidInventory) as exc:
            self.record_refusal(attempt, actor, reason_for(exc), subject, now=now)
            raise

    def record_refusal(self, attempt: str, actor: Any, reason: str, subject: Any = None, *,
                       now: dt.datetime | None = None) -> None:
        """Write one append-only `action.refused` row, or account for not writing it.

        For the inputs this path supports — a string `attempt`/`reason` from the platform's own
        vocabularies or anything outside them, an `Actor`-shaped actor or anything else, any subject —
        and for the persistence failures it handles below, this method raises nothing back into the
        denial it is recording. That is the whole promise, and it is deliberately narrower than "never
        raises": an object whose own `__eq__`/`__hash__` throws, or an injected clock or logger that is
        broken (both are test seams, not production surfaces), can still propagate out of here, and the
        caller's `raise` will not run. The guard is in `refusals.refusal_row`, which type-tests before it
        consults the closed sets, so `[]`/`{}` as a reason is an unauditable count rather than a
        `TypeError` replacing the refusal a client was owed.

        Three outcomes are possible and all three are counted, so no loss is silent:

        * **no honest row** — the caller's identity is not a platform `Actor` with a bounded identity
          and a known role (`refusals.attribution` answers `None`), or the attempt/reason pair is
          outside the closed vocabularies (including a reason that is not a string at all). Nothing is
          written and nothing is invented: a hashed or
          placeholder actor would be a claim about a person, and `unauditable` is the truthful word.
        * **no quota** — the process-local token bucket is empty. The refusal still happens; the row
          does not, and `dropped` counts it.
        * **the write failed** — locked, full or corrupt database. `failed` counts it, one bounded log
          line names the exception class (spaced at least `refusals.FAILURE_LOG_INTERVAL_SECONDS` of real
          elapsed time apart), and the original denial is re-raised by the caller anyway.
          A failed write still spent its token, so a broken database costs refusals rather than a
          retry storm.

        `now` is the instant the refused method was asked to run at, used as the row's stamp exactly as
        every other audit row in this module uses it; a value that is not an aware `datetime` is
        ignored in favour of the real clock, and it never reaches the rate budget (which reads only a
        monotonic clock — see `refusals.RefusalAudit`).
        """
        from .refusals import OPERATION, refusal_row
        row = refusal_row(attempt, reason, actor, subject)
        if row is None:
            self._refusal_audit.count('unauditable')
            return
        actor_field, subject_field, detail = row
        if not self._refusal_audit.reserve():
            self._refusal_audit.count('dropped')
            return
        moment = now if isinstance(now, dt.datetime) and now.tzinfo is not None else None
        try:
            with self.transaction() as connection:
                self.audit(connection, clock(moment), actor_field, OPERATION, subject_field, detail)
        except Exception as exc:
            # `Exception`, not `BaseException`: a KeyboardInterrupt must still land, and this branch
            # exists for driver errors. Nothing is retried — a retry loop against a locked database
            # turns an audit gap into an outage — and nothing here may speak for the denial, which the
            # caller re-raises. Only the exception *class* is named, per the logging contract: driver
            # messages can echo file paths and other things an audit surface should not carry.
            self._refusal_audit.count('failed')
            if self._refusal_audit.should_log_failure():
                log.warning('Refusal audit write failed', extra={'error_class': type(exc).__name__})
        else:
            self._refusal_audit.count('written')

    def refusal_audit_status(self) -> dict[str, Any]:
        """Report this process's refusal-audit counters and write budget, without touching the database.

        A pure in-memory read, deliberately: a `GET /v1/runtime` poll must not cost a commit, and the
        numbers are per-process by construction (`refusals.RefusalAudit`), so reading them is not a
        query. They are also volatile: after a restart they read zero again while the rows already
        committed stay in `audit` forever, which is why the body names its own scope.
        """
        return self._refusal_audit.status()

    def intake(self, event: dict[str, Any], actor: Actor, *, now: dt.datetime | None = None,
               admission: Callable[[sqlite3.Connection, dict[str, Any]], None] | None = None) -> dict[str, Any]:
        """File one canonical event, its condition, its incident and the delivery its transition booked.

        `admission` is an internal seam for `platform/suppression.file_event` and for
        `Store.grouping_admission`: a callable taking
        ``(connection, outcome)`` — this transaction's own open connection and the accepted outcome it is
        about to return — called **after** the `event.intake` audit row and **before** the commit, so a
        decision made there reads the rows this call wrote while nobody else can see them and its fold
        commits with the filing; a separate transaction would leave the booked row `pending` and leasable
        by `claim_notification` in the gap. It is not configuration and not a product surface: callers
        that pass nothing (`lo-platform intake` without `--index`) see exactly what they saw before, and an
        admitted callback runs inside this transaction, so it reads uncommitted rows
        on this connection only, may not open a nested transaction or a second connection, and anything it
        raises rolls back the whole admission — event, condition, incident, outbox row and audits alike.
        Since correlation the two HTTP intake routes pass the grouping callback, so an event admitted over HTTPS
        may land on an open incident instead of opening one; `incident_id` is the one outcome key a callback
        may rewrite, which is why it is handed the dict at all.

        Raises:
            StateError: A refusal this method already raised, unchanged, or anything the admitted
                callback raised — which arrives having rolled back everything this call wrote.
        """
        require(actor, 'producer')
        now = clock(now)
        validate_event(event, now)
        if event['source'] != actor.identity:
            raise StateError('Source identity differs from authenticated producer')
        fingerprint = digest(event)
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, canonical([event['source'], event['source_event_id']])))
        # Each rule version and resource has its own ordering domain, never arrival order.
        key = digest([event['source'], event['rule_id'], event['rule_version'],
                      event['resource_id'], event['condition']])
        watermark = utc_text(timestamp(event['window']['end']))
        with self.transaction() as connection:
            old = connection.execute('SELECT * FROM events WHERE source=? AND source_event_id=?',
                                     (event['source'], event['source_event_id'])).fetchone()
            if old:
                if old['fingerprint'] != fingerprint:
                    raise StateError('Event retry changed contents')
                return {'status': 'duplicate', 'event_id': old['id'], 'incident_id': old['incident_id']}
            condition = connection.execute('SELECT * FROM conditions WHERE key=?', (key,)).fetchone()
            if condition and condition['watermark'] == watermark:
                raise StateError('Conflicting evaluations at the same condition watermark')
            connection.execute('INSERT INTO events VALUES (?,?,?,?,?,?,NULL)',
                (event_id, event['source'], event['source_event_id'], fingerprint, utc_text(now), canonical(event)))
            transition, incident_id = None, None
            if not condition or watermark > condition['watermark']:
                incident_id = condition['incident_id'] if condition else None
                if event['status'] == 'firing' and not incident_id:
                    incident_id = str(uuid.uuid4())
                    connection.execute('INSERT INTO incidents VALUES (?,?,?,?,?,?,?)',
                        (incident_id, key, event['resource_id'], 'open', utc_text(now), utc_text(now), event_id))
                    transition = 'opened'
                elif incident_id and event['status'] == 'resolved':
                    # correlation's half of grouping: an incident several conditions point at stays open until
                    # the last of them resolves. `conditions.incident_id` is the membership, so the count
                    # below is the group — and `status<>'resolved'` keeps a condition whose last verdict
                    # was `unknown` counted as open, which is the loud direction for a recovery notice.
                    # A v1 file has one condition per incident and so answers 0 here: the pre-grouping
                    # behaviour is this branch's no-members case, unchanged, not a special case.
                    open_members = connection.execute(
                        "SELECT count(*) FROM conditions WHERE incident_id=? AND key<>? AND status<>'resolved'",
                        (incident_id, key)).fetchone()[0]
                    if open_members:
                        # The group keeps its subject: this member's recovery is a fact about the group, and
                        # `incidents.last_event_id` is how escalation and dependency suppression name the
                        # condition that opened it. `updated_at` says the group changed; the pointer stays.
                        connection.execute('UPDATE incidents SET updated_at=? WHERE id=?',
                                           (utc_text(now), incident_id))
                    else:
                        connection.execute("UPDATE incidents SET status='resolved',updated_at=?,last_event_id=?"
                                           ' WHERE id=?', (utc_text(now), event_id, incident_id))
                    transition = 'resolved' if not open_members else None
                elif incident_id:
                    connection.execute('UPDATE incidents SET updated_at=?,last_event_id=? WHERE id=?',
                                       (utc_text(now), event_id, incident_id))
                connection.execute('INSERT OR REPLACE INTO conditions VALUES (?,?,?,?,?)',
                    (key, watermark, event_id, event['status'],
                     None if event['status'] == 'resolved' else incident_id))
                connection.execute('UPDATE events SET incident_id=? WHERE id=?', (incident_id, event_id))
                if transition:
                    delivery_id = notification_id(event_id)
                    payload = {'schema_version': 1, 'delivery_id': delivery_id, 'incident_id': incident_id,
                               'transition': transition, 'event_id': event_id, 'event': event}
                    connection.execute('INSERT INTO outbox(id,incident_id,payload,status,available_at)'
                                       ' VALUES (?,?,?,?,?)',
                                       (delivery_id, incident_id, canonical(payload), 'pending', utc_text(now)))
            self.audit(connection, now, actor.identity, 'event.intake', event_id, {'transition': transition})
            outcome = {'status': 'accepted', 'event_id': event_id, 'incident_id': incident_id,
                       'transition': transition}
            if admission is not None:
                # The commit happens on leaving this `with connection:`, so a callback reached here
                # decides before the rows are durable and its failure unwinds the whole admission.
                admission(connection, outcome)
            return outcome

    def grouping_admission(self, index_path: Path | str | None, actor: Actor, *,
                           now: dt.datetime | None = None, graph: Any = None,
                           grouping: correlation.Grouping | None = None
                           ) -> Callable[[sqlite3.Connection, dict[str, Any]], None] | None:
        """Return the `intake` `admission` callback that groups the event it files, or None.

        Grouping is a *call site of intake's own seam* and nothing else, which is the whole reason it can
        be trusted as one writer: the decision runs on intake's open connection, after its audit row and
        before its commit, so the joined group and the event that joined it become visible to every other
        process in the same instant, and no reconciler, scheduler or in-memory engine ever opens an
        incident this transaction did not. `owner.py`'s lock keeps one service writing the file; this is
        how grouping obeys that lock rather than working around it.

        Nothing is stored in memory between calls, so the group a restart sees is the group the file
        holds, and two intakes racing for one group cannot both open an incident: SQLite's
        `BEGIN IMMEDIATE` serialises the transactions, and the second one reads the first one's committed
        incident as a candidate (`tests/test_correlation.py` proves it with threads).

        Every failure mode is *no grouping*. With no declared graph the callback is not installed at all
        (an installation that declared no topology is not making a claim about cause), a search cut by
        `GROUP_CANDIDATES` files its own incident, a truncated graph walk is refused as an answer by
        `correlation.topological`, an over-full group is left alone, and an inexpressible rationale is
        never written. Each of those costs an operator a second page and none of them costs them a wrong
        cause, which is the asymmetry the whole rule is built on: co-occurrence alone produces one
        mush-incident per busy hour.

        Args:
            index_path: The built inventory index the declared graph is read from, or ``None``.
            actor: The producer whose event is being filed — the same `Actor` the caller passes to
                `intake`, so the grouping audit row names the identity the intake row names.
            now: The instant to stamp the link and its audit row with; intake's own `now` should be passed
                so one event carries one timestamp across its event, incident, member and audit rows.
            graph: A prepared `topology.Topology`, for a caller grouping many events over one index. It
                wins over `index_path`, exactly as `platform/suppression.file_event` takes one.
            grouping: The bounds to apply; the default is `correlation.Grouping()` and every bound is
                checked where the callback is wired, not at the first event.

        Raises:
            StateError: `actor` is not a producer, or `index_path` and `graph` are both absent while a
                `grouping` was asked for — refused at wiring time, before any event is at stake.
            CorrelationError: A bound is outside its range. Raised here, on purpose, by whoever configured
                it rather than by a transaction that had already filed a finding.
        """
        require(actor, 'producer')
        rules = grouping or correlation.Grouping()
        if not index_path and graph is None:
            return None
        moment = clock(now)
        graph = graph or topology.Topology(index_path, depth=rules.max_hops)

        def admit(connection: sqlite3.Connection, outcome: dict[str, Any]) -> None:
            """Join the incident this very transaction opened to the first group that corroborates it."""
            if outcome.get('status') != 'accepted' or outcome.get('transition') != 'opened':
                return                       # nothing new was opened, so there is nothing to join
            event_id = outcome['event_id']
            condition = connection.execute('SELECT key FROM conditions WHERE event_id=?', (event_id,)).fetchone()
            if condition is None:
                return                       # intake wrote no condition for this event: nothing to re-point
            event = json.loads(connection.execute('SELECT payload FROM events WHERE id=?',
                                                 (event_id,)).fetchone()['payload'])
            if correlation.is_escalation_rung(event.get('rule_id')):
                return                       # a rung is its own condition, by `escalation.py`'s design
            fresh = outcome['incident_id']
            # Oldest open incident first, and the first one that corroborates wins: an arriving condition
            # that could join two groups must always pick the same one, or a replay of the same event
            # after a restart would land it somewhere else. Candidates past `GROUP_CANDIDATES` are never
            # looked at, and the event keeps its own incident — the bound costs a page, never a cause.
            for candidate in connection.execute(GROUP_CANDIDATE_SQL, (fresh, GROUP_CANDIDATES)):
                if correlation.is_escalation_rung(candidate['rule_id']):
                    continue                 # exempt on both sides: a rung's incident anchors no group
                if self._join_group(connection, fresh=fresh, candidate=candidate, event=event,
                                    event_id=event_id, condition_key=condition['key'], actor=actor.identity,
                                    grouping=rules, graph=graph, at=moment):
                    outcome['incident_id'] = candidate['incident_id']
                    return
        return admit

    def _join_group(self, connection: sqlite3.Connection, *, fresh: str, candidate: Any, event: dict[str, Any],
                    event_id: str, condition_key: str, actor: str, grouping: correlation.Grouping,
                    graph: Any, at: dt.datetime) -> bool:
        """Move the condition this transaction created onto `candidate`'s incident, or refuse to.

        Six statements, one transaction, in this order and no other:

        1. the membership (`conditions.incident_id`) — the many-to-one pointer §5 already had,
        2. the event's own pointer, so `events.incident_id` never names a row about to disappear,
        3. the outbox row intake booked seconds ago, which carries the incident id inside its payload too
           and is *not* rewritten: the payload is the delivery's record of what was decided when it was
           booked, and its `transition` stays `opened` because the member's own page is still the alert
           that condition earned (grouping is context, pages stay per condition — `docs/CONTRACTS.md` §4),
        4. the target's `updated_at`, deliberately **without** moving `last_event_id`: that pointer is how
           `platform/suppression._firing_resources` and `escalation_reader` name an incident's subject, and
           letting the most recent symptom overwrite the cause would make a group's blame depend on which
           producer sent first. The member's own event is reachable through `conditions.event_id`,
        5. the now-empty incident row, deletable because the foreign key from `outbox` was moved off it in
           step 3 and because nothing outside this transaction could ever have seen it (`BEGIN IMMEDIATE`),
        6. the rationale row, which is the reason anybody will still be able to read this group later.

        Returns False — leaving the event its own incident, and the operator two pages — when the group is
        already full or the composed rationale would not fit its column. Never raises on the data path:
        an exception here would roll back the finding that `intake` had already validated, and a lost
        finding is not what a grouping heuristic is allowed to cost.
        """
        target = candidate['incident_id']
        member = json.loads(candidate['payload'])
        signals = grouping.link(event, member, graph)
        if signals is None:
            return False
        try:
            document = correlation.rationale_document(signals)
        except correlation.CorrelationError:
            return False
        if not 1 <= len(document) <= correlation.MAX_RATIONALE_CHARS:
            return False
        members = connection.execute("SELECT count(*) FROM conditions WHERE incident_id=? AND status<>'resolved'",
                                     (target,)).fetchone()[0]
        if members >= grouping.max_members:
            return False
        connection.execute('UPDATE conditions SET incident_id=? WHERE key=? AND incident_id=?',
                           (target, condition_key, fresh))
        connection.execute('UPDATE events SET incident_id=? WHERE id=?', (target, event_id))
        connection.execute('UPDATE outbox SET incident_id=? WHERE incident_id=?', (target, fresh))
        connection.execute('UPDATE incidents SET updated_at=? WHERE id=?', (utc_text(at), target))
        connection.execute('DELETE FROM incidents WHERE id=?', (fresh,))
        connection.execute(f'INSERT OR REPLACE INTO {GROUPING_TABLE}(incident_id,condition_key,rationale,at)'
                           ' VALUES (?,?,?,?)', (target, condition_key, document, utc_text(at)))
        self.audit(connection, at, actor, GROUPING_OPERATION, event_id,
                   {'incident_id': target, 'via': [signal.kind for signal in signals],
                    'members': members + 1})
        return True

    def prune_reservations(self, connection: sqlite3.Connection, now: dt.datetime) -> int:
        """Delete send slots no budget can count again, inside the caller's transaction (ledger state leftovers).

        Since schema v2 every reserved delivery leaves a row in `notification_reservations` and the
        human-channel budget is a count over those rows, so the table grew for the life of the file and
        nothing removed it. A slot is retired only when it sits strictly before the instant that budget
        counts from: `notification_safety._window_start` — the same function `reserve` calls, imported
        rather than re-derived so the two can never disagree — which is the later of the end of the
        configured window and the channel's last human reset. Both instants only move forward as the
        clock runs, so a row deleted here could not have been counted by any later claim either: the
        window may age, a budget may never silently restart.

        Three kinds of row are deliberately kept. Slots taken inside an approved test window are never
        deleted, because that budget counts every row carrying its id with no age bound at all, so any
        age-based prune of it hands back sends that were already spent. Rows of a channel no policy is
        configured for here are kept too: its window is not knowable here, and guessing one is how a
        budget restarts — with several channels configured (ledger notifications) each one this store knows
        about is pruned against its own window, and a slot belonging to a channel nobody here has a
        policy for stays exactly where it was. And `notification_suppressions` has no prune anywhere,
        because a suppressed delivery must never replay whatever its age.

        No audit row is written: the `notification.reserved` rows the audit log keeps and never prunes
        are the same facts, so this removes a duplicate rather than a record. Sink-named slots of this
        channel do go with the aged human ones (nothing counts them at any age), which leaves an old
        delivered row labelled only by its outbox fields in `presentation.delivery_route`; a refusal
        keeps its wording either way, since suppressions stay.

        Returns the number of rows deleted. The delivery loop calls this where it claims the outbox.
        """
        from .notification_safety import _window_start, circuit_state
        deleted = 0
        for policy in self.channel_policies.values():
            start = utc_text(_window_start(now, circuit_state(connection, policy.channel)['reset_at'],
                                           policy.window_seconds))
            deleted += connection.execute('DELETE FROM notification_reservations '
                                          "WHERE channel=? AND test_window IS NULL AND julianday(at)<julianday(?)",
                                          (policy.channel, start)).rowcount
        return deleted

    def claim_notification(self, *, now: dt.datetime | None = None, lease_seconds: int = 30,
                           max_attempts: int = 5, callback_seconds: int = CALLBACK_TTL_SECONDS) -> dict[str, Any]:
        """Hand out the head of the queue under a lease, or report nothing to send.

        Since schema v3 the claim is also the moment the delivery acquires its identity in two more
        ways: the channel it is routed to (recorded on the row, so a later reader can see which budget
        and which breaker the send ran against) and, for a human-channel send, a single-use callback
        token whose hash is stored beside it. The token is returned exactly once, to the caller that
        claimed the row; nothing else ever holds it and the database cannot show it again.

        Args:
            now: The instant to claim at; defaults to the clock.
            lease_seconds: How long the claim stays live (5..300).
            max_attempts: Attempts after which the row goes `dead`.
            callback_seconds: How long an issued callback token stays spendable (60..86400).

        Raises:
            StateError: The bounds are outside what this method accepts.
        """
        now = clock(now)
        if not 5 <= lease_seconds <= 300 or not 1 <= max_attempts <= 20:
            raise StateError('Invalid delivery bounds')
        if not CALLBACK_TTL_BOUNDS[0] <= callback_seconds <= CALLBACK_TTL_BOUNDS[1]:
            raise StateError('Callback lifetime must be 60..86400 seconds')
        with self.transaction() as connection:
            # Housekeeping first: the budget queries below read the table this trims, and they read it
            # the same way whether or not anything was removed.
            self.prune_reservations(connection, now)
            expired = connection.execute("SELECT * FROM outbox WHERE status='sending' AND lease_until<=?",
                                         (utc_text(now),)).fetchall()
            for row in expired:
                connection.execute("UPDATE notification_attempts SET result='unknown',finished_at=?"
                                   " WHERE claim_token=? AND result='sending'",
                                   (utc_text(now), row['claim_token']))
                connection.execute("UPDATE outbox SET status=?,claim_token=NULL,lease_until=NULL WHERE id=?",
                                   ('dead' if row['attempts'] >= max_attempts else 'pending', row['id']))
            row = connection.execute("""SELECT o.* FROM outbox o WHERE o.status='pending' AND o.available_at<=?
                AND NOT EXISTS (SELECT 1 FROM outbox p WHERE p.incident_id=o.incident_id
                    AND p.sequence<o.sequence AND p.status!='sent'
                    AND NOT EXISTS (SELECT 1 FROM notification_suppressions s WHERE s.outbox_id=p.id))
                ORDER BY o.sequence LIMIT 1""", (utc_text(now),)).fetchone()
            if not row:
                return None
            from .notification_safety import reserve_route
            route, reason = reserve_route(self, connection, row, self.channel_policies, now)
            if reason:
                connection.execute("UPDATE outbox SET status='dead',claim_token=NULL,lease_until=NULL WHERE id=?",
                                   (row['id'],))
                record_suppression(connection, row['id'], reason, now)
                self.audit(connection, now, 'notification-worker', 'notification.suppressed', row['id'],
                           {**route, 'reason': reason})
                return {'id': row['id'], 'suppressed': reason, 'destination': route['destination']}
            token = secrets.token_urlsafe(32)
            # A token is minted for a send that can reach a human and be answered. A sink-bound row gets
            # none, and one that is retried overwrites the token of the attempt before it: the superseded
            # token no longer matches anything stored, so an answer to a send the operator has already
            # given up on cannot arrive later and spend itself against this delivery.
            callback: dict[str, str] | None = None
            if route['destination'] == 'human':
                secret = secrets.token_urlsafe(32)
                expires = now + dt.timedelta(seconds=callback_seconds)
                connection.execute('UPDATE outbox SET callback_token_hash=?,callback_expires_at=?'
                                   ',callback_consumed_at=NULL WHERE id=?',
                                   (digest(secret), utc_text(expires), row['id']))
                callback = {'token': secret, 'expires_at': utc_text(expires)}
            connection.execute("UPDATE outbox SET status='sending',attempts=attempts+1,lease_until=?"
                               ",claim_token=?,channel=? WHERE id=?",
                               (utc_text(now + dt.timedelta(seconds=lease_seconds)), token,
                                route['channel'], row['id']))
            connection.execute('INSERT INTO notification_attempts(id,outbox_id,started_at,finished_at,result,'
                               'claim_token,cause) VALUES (?,?,?,?,?,?,?)',
                               (str(uuid.uuid4()), row['id'], utc_text(now), None, 'sending', token, 'pending'))
            claimed: dict[str, Any] = {'id': row['id'], 'payload': json.loads(row['payload']),
                                       'claim_token': token, 'destination': route['destination'],
                                       'channel': route['channel']}
            if callback:
                claimed['callback'] = callback
            return claimed

    def finish_notification(self, delivery_id: str, claim_token: str, success: bool, *,
                            now: dt.datetime | None = None, max_attempts: int = 5,
                            cause: str | None = None) -> str:
        """Close one claimed delivery attempt and say, when it failed, which class of failure it was.

        `cause` is the bounded word the operator reads later (`ATTEMPT_CAUSES`, minus `pending`, which
        only an in-flight attempt holds). A caller that does not know — an older caller, or a transport
        that reported nothing — gets `rejected`, the refusal-prone answer: "the provider did not accept
        this" is what the boolean alone always said, and upgrading it to `transport` requires the caller
        to have actually seen a transport failure. No response body, URL or credential is accepted here,
        so this field cannot become a place to park provider output.

        Raises:
            StateError: The claim is no longer valid, or `cause` is not one of the bounded words.
        """
        now = clock(now)
        if success:
            recorded = 'accepted' if cause in (None, 'accepted') else None
        else:
            recorded = cause or 'rejected'
        if recorded not in ATTEMPT_CAUSES or recorded == 'pending':
            raise StateError('Invalid delivery attempt cause')
        with self.transaction() as connection:
            row = connection.execute('SELECT * FROM outbox WHERE id=?', (delivery_id,)).fetchone()
            if (not row or row['status'] != 'sending' or row['claim_token'] != claim_token
                    or row['lease_until'] <= utc_text(now)):
                raise StateError('Delivery claim is no longer valid')
            status = 'sent' if success else ('dead' if row['attempts'] >= max_attempts else 'pending')
            connection.execute('UPDATE outbox SET status=?,available_at=?,lease_until=NULL,claim_token=NULL WHERE id=?',
                (status, utc_text(now + dt.timedelta(seconds=min(300, 2 ** row['attempts']))), delivery_id))
            connection.execute('UPDATE notification_attempts SET result=?,finished_at=?,cause=? WHERE claim_token=?',
                               ('accepted' if success else 'failed', utc_text(now), recorded, claim_token))
            self.audit(connection, now, 'notification-worker', 'notification.' + status, delivery_id)
            return status

    def record_callback(self, channel: str, token: str, action_id: str, actor: Actor, *,
                        now: dt.datetime | None = None) -> dict[str, Any] | None:
        """Spend one notification callback token on an *intent to approve*; never on a decision.

        The token is what a channel carried to the phone, so holding it proves that the sender reached
        a human surface — it proves nothing about who is answering, which is why the identity written
        into the audit row is `actor.identity` from the authenticated transport and no body field is
        ever read as an identity. The action must belong to the incident this delivery announced, and
        must still be pending. What this records is one append-only `action.approval_intent` audit row:
        the action stays `pending`, and the decision still needs `decide` from a human credential.

        Returns:
            The recorded intent, or `None` when the token matches no live delivery on this channel. The
            caller answers 401 for `None`; one sentence covers a wrong token, an unknown channel and a
            token minted for another channel, so this refusal is not an oracle for any of the three.

        Raises:
            StateError: The actor may not propose at all, the token is expired or already spent, or the
                action is not the one this delivery could have been about.
        """
        require(actor, 'human', 'proposer', 'executor')
        now = clock(now)
        channel_name, action_uuid = label(channel), identifier(action_id)
        if not isinstance(token, str) or not 16 <= len(token) <= 256:
            return None
        candidate = digest(token)
        with self.transaction() as connection:
            row = connection.execute("SELECT * FROM outbox WHERE callback_token_hash=? AND "
                                     "callback_token_hash<>''", (candidate,)).fetchone()
            # The index lookup narrows the candidate; the constant-time comparison is the decision, and
            # it is what keeps a caller who can watch timing from learning a stored hash one prefix at a
            # time. A token minted for a different channel is refused here rather than at the route, so
            # the answer never confirms that some other channel exists.
            if (row is None or not secrets.compare_digest(row['callback_token_hash'], candidate)
                    or row['channel'] != channel_name):
                return None
            # Both stamps are this module's own `utc_text` form, so they compare as the strings the rest
            # of the file already compares (`lease_until <= utc_text(now)`); a value this build cannot
            # read is treated as expired, which is the refusal-prone direction for a spendable token.
            if not row['callback_expires_at'] or row['callback_expires_at'] <= utc_text(now):
                raise StateError('Notification callback has expired')
            if row['callback_consumed_at']:
                raise StateError('Notification callback has already been consumed')
            action = connection.execute('SELECT * FROM actions WHERE id=?', (action_uuid,)).fetchone()
            if action is None:
                raise StateError('Action is not part of the notified incident')
            # An action names its incident inside its own canonical payload, which is the document the
            # approval fingerprint covers: reading the binding from anywhere else would let an intent be
            # recorded against an action this delivery never announced.
            if json.loads(action['payload'])['incident_id'] != row['incident_id']:
                raise StateError('Action is not part of the notified incident')
            if action['status'] != 'pending':
                raise StateError('Action is not pending')
            connection.execute('UPDATE outbox SET callback_consumed_at=? WHERE id=?', (utc_text(now), row['id']))
            self.audit(connection, now, actor.identity, 'action.approval_intent', action_uuid, {
                'channel': channel_name, 'delivery_id': row['id'], 'decided': False})
            return {'status': 'intent_recorded', 'action_id': action_uuid, 'delivery_id': row['id'],
                    'decided': False}

    def retry_notification(self, delivery_id: str, actor: Actor, *,
                           now: dt.datetime | None = None) -> dict[str, Any]:
        require(actor, 'human')
        now = clock(now)
        with self.transaction() as connection:
            refused = connection.execute('SELECT 1 FROM notification_suppressions WHERE outbox_id=?',
                                         (delivery_id,)).fetchone()
            if refused:
                raise StateError('Suppressed notifications cannot be replayed; inspect retained evidence')
            row = connection.execute('SELECT status FROM outbox WHERE id=?', (delivery_id,)).fetchone()
            if not row or row[0] != 'dead':
                raise StateError('Only exhausted notifications can be manually retried')
            connection.execute("UPDATE outbox SET status='pending',attempts=0,available_at=? WHERE id=?",
                               (utc_text(now), delivery_id))
            self.audit(connection, now, actor.identity, 'notification.retry_requested', delivery_id)
            return {'status': 'pending'}

    def reset_notification_guard(self, actor: Actor, *,
                                 now: dt.datetime | None = None) -> dict[str, Any]:
        """Unlatch every configured channel's flood breaker on explicit human authority, discarding the
        pending backlog.

        The reset is also the instant the send budget starts counting from (ledger control state): the slots
        taken before it are history, so a reset buys a fresh window instead of only waiting for the
        old one to age out. The audit log keeps both the discarded rows and the reset itself.

        Since schema v3 a store may carry more than one channel, and this button is one decision about
        the whole platform: the backlog it discards was never addressed to a channel yet, so unlatching
        only the primary would discard deliveries a healthy channel could still have sent. Every
        configured channel is unlatched and every one is audited separately, so an operator reading the
        log can see which breakers a single click cleared.
        """
        require(actor, 'human')
        now = clock(now)
        with self.transaction() as connection:
            if connection.execute("SELECT 1 FROM outbox WHERE status='sending'").fetchone():
                raise StateError('Stop delivery and reconcile outstanding claims before reset')
            for row in connection.execute("SELECT id FROM outbox WHERE status='pending'").fetchall():
                connection.execute("UPDATE outbox SET status='dead' WHERE id=?", (row['id'],))
                record_suppression(connection, row['id'], 'backlog-discarded-on-explicit-reset', now)
                self.audit(connection, now, actor.identity, 'notification.suppressed', row['id'],
                           # A backlog discard is not about one channel: the label names the store's
                           # primary, which is the only channel this row could be said to belong to.
                           {'reason': 'backlog-discarded-on-explicit-reset',
                            'channel': self.notification_policy.channel})
            from .notification_safety import reset_circuit
            for channel in self.channel_policies:
                reset_circuit(connection, channel, now)
                self.audit(connection, now, actor.identity, 'notification.circuit_reset', channel)
            return {'status': 'reset', 'backlog_replayed': False}

    def notification_safety_status(self) -> dict[str, Any]:
        """Report this store's delivery posture: the primary channel's view, plus every channel's own.

        `channel`, `delivery_mode`, `circuit_open` and `test_window` stay exactly the fields they were,
        read against the store's own (primary) channel, because that is what the operator surfaces and
        the staging scripts ask. `channels` is the per-channel map (ledger notifications): a second channel's
        latched breaker is visible without changing the meaning of the first four keys.
        """
        from .notification_safety import circuit
        with self.transaction() as connection:
            count = connection.execute('SELECT count(*) FROM notification_suppressions').fetchone()[0]
            return {'channel': self.notification_policy.channel,
                    'delivery_mode': self.notification_policy.delivery_mode,
                    'circuit_open': circuit(connection, self.notification_policy.channel),
                    'suppressed': count, 'synthetic_default': 'recording-sink',
                    'test_window': self.notification_policy.test_window,
                    'channels': {name: {'circuit_open': circuit(connection, name),
                                        'delivery_mode': policy.delivery_mode,
                                        'max_attempts': policy.max_attempts,
                                        'window_seconds': policy.window_seconds}
                                 for name, policy in self.channel_policies.items()}}

    def start_notification_mode(self, *, now: dt.datetime | None = None) -> None:
        """Call under the service owner lock; reopening Store must not change modes."""
        now = clock(now)
        mode = self.notification_policy.delivery_mode
        with self.transaction() as connection:
            prior = control_read(connection, CONTROL_MODE)
            if prior:
                if prior in ('off', 'recording') and mode == 'live':
                    pending = connection.execute(
                        "SELECT count(*) FROM outbox WHERE status IN ('pending','sending')").fetchone()[0]
                    if pending:
                        raise StateError(
                            'Live activation refused: explicitly reconcile paused notification backlog first')
                if prior == mode:
                    return
            control_write(connection, CONTROL_MODE, mode, now)
            self.audit(connection, now, 'platform-runtime', 'notification.mode', 'platform', {'mode': mode})

    def expire_actions(self, *, now: dt.datetime | None = None) -> int:
        now = clock(now)
        with self.transaction() as connection:
            rows = connection.execute("SELECT id FROM actions WHERE status IN ('pending','approved')"
                                      " AND expires_at<=?", (utc_text(now),)).fetchall()
            for row in rows:
                connection.execute("UPDATE actions SET status='expired' WHERE id=?", (row[0],))
                self.audit(connection, now, 'platform', 'action.expired', row[0])
            return len(rows)

    def propose_action(self, request: dict[str, Any], actor: Actor,
                       policy: Callable[[dict[str, Any]], Any], *,
                       now: dt.datetime | None = None) -> dict[str, Any]:
        with self.refusal('propose', actor, now=now):
            require(actor, 'proposer', 'human')
            now = clock(now)
            required = {'retry_key', 'incident_id', 'action', 'version', 'targets', 'parameters', 'evidence',
                        'expires_at'}
            if not isinstance(request, dict) or set(request) != required:
                raise StateError('Invalid action request fields')
            label(request['retry_key'])
            identifier(request['incident_id'])
            expires = timestamp(request['expires_at'])
            if not now < expires <= now + dt.timedelta(hours=24):
                raise StateError('Action expiry must be in the next 24 hours')
            policy(request)
            fingerprint = digest(request)
            with self.transaction() as connection:
                old = connection.execute('SELECT * FROM actions WHERE requester=? AND retry_key=?',
                                         (actor.identity, request['retry_key'])).fetchone()
                if old:
                    if old['fingerprint'] != fingerprint:
                        raise StateError('Action retry changed contents')
                    return {'action_id': old['id'], 'status': old['status']}
                incident = connection.execute('SELECT * FROM incidents WHERE id=?',
                                              (request['incident_id'],)).fetchone()
                if not incident or incident['status'] != 'open':
                    raise StateError('Action requires an open incident')
                if (not request['evidence'] or not isinstance(request['evidence'], list)
                        or len(request['evidence']) > 20):
                    raise StateError('Action requires bounded incident event evidence')
                for event_id in request['evidence']:
                    identifier(event_id)
                    if not connection.execute('SELECT 1 FROM events WHERE id=? AND incident_id=?',
                                              (event_id, incident['id'])).fetchone():
                        raise StateError('Action evidence must belong to incident')
                action_id = str(uuid.uuid4())
                connection.execute('INSERT INTO actions VALUES (?,?,?,?,?,?,?,?,NULL)',
                    (action_id, actor.identity, request['retry_key'], fingerprint, canonical(request),
                     'pending', utc_text(now), utc_text(expires)))
                # Proposal-time verification capture, in this same transaction and before the
                # `action.proposed` row: a proposal and the meaning it binds to commit together or not
                # at all. Only a mounted policy captures anything — a default-off store reaches none of
                # the new tables at all, which is what lets a build simulating the pre-v4 schema propose
                # exactly as it did before — and the capture writes an explicit `unbound` row rather than
                # refusing a proposal it cannot bind. An incomplete schema still refuses: the
                # request's stored payload and its approval fingerprint are untouched, so an operator
                # approving this action approves exactly what the proposer sent.
                if self.verification_policy is not None:
                    from .verification_records import capture_binding
                    capture_binding(connection, self.verification_policy, action_id, request, now)
                self.audit(connection, now, actor.identity, 'action.proposed', action_id,
                           {'parameters_hash': digest(request['parameters'])})
                return {'action_id': action_id, 'status': 'pending'}

    def decide(self, action_id: str, decision: str, actor: Actor, *,
               now: dt.datetime | None = None) -> dict[str, Any]:
        with self.refusal('decide', actor, action_id, now=now):
            require(actor, 'human')
            if decision not in ('approved', 'denied'):
                raise StateError('Invalid decision')
            now = clock(now)
            with self.transaction() as connection:
                row = connection.execute('SELECT * FROM actions WHERE id=?', (action_id,)).fetchone()
                if not row or row['status'] != 'pending':
                    raise StateError('Action is not pending')
                outcome = 'expired' if row['expires_at'] <= utc_text(now) else decision
                connection.execute('UPDATE actions SET status=?,decided_by=? WHERE id=?',
                                   (outcome, actor.identity, action_id))
                self.audit(connection, now, actor.identity, 'action.' + outcome, action_id)
                return {'status': outcome}

    def claim_action(self, action_id: str, actor: Actor, policy: Callable[[dict[str, Any]], Any], *,
                     now: dt.datetime | None = None) -> dict[str, Any]:
        with self.refusal('claim', actor, action_id, now=now):
            require(actor, 'executor')
            now = clock(now)
            with self.transaction() as connection:
                row = connection.execute('SELECT * FROM actions WHERE id=?', (action_id,)).fetchone()
                if not row or row['status'] != 'approved':
                    raise StateError('Action is not available for dispatch')
                if row['expires_at'] <= utc_text(now):
                    connection.execute("UPDATE actions SET status='expired' WHERE id=?", (action_id,))
                    self.audit(connection, now, actor.identity, 'action.expired', action_id)
                    return {'status': 'expired'}
                payload = json.loads(row['payload'])
                policy(payload)
                if connection.execute('SELECT status FROM incidents WHERE id=?',
                                      (payload['incident_id'],)).fetchone()[0] != 'open':
                    raise StateError('Incident recovered; propose again only if needed')
                execution_id, token = str(uuid.uuid4()), secrets.token_urlsafe(32)
                connection.execute('INSERT INTO executions VALUES (?,?,?,?,?,?,?)',
                    (execution_id, action_id, actor.identity, digest(token), 'executing', utc_text(now), utc_text(now)))
                connection.execute("UPDATE actions SET status='executing' WHERE id=?", (action_id,))
                self.audit(connection, now, actor.identity, 'execution.claimed', execution_id)
                return {'execution_id': execution_id, 'runner_token': token, 'status': 'executing',
                        'request': payload}

    def execution_outcome(self, execution_id: str, outcome: str, actor: Actor,
                          token: str | None = None, *,
                          now: dt.datetime | None = None) -> dict[str, Any]:
        with self.refusal('outcome', actor, execution_id, now=now):
            require(actor, 'executor', 'human')
            if outcome not in ('succeeded', 'failed', 'unknown'):
                raise StateError('Invalid execution outcome')
            now = clock(now)
            with self.transaction() as connection:
                row = connection.execute('SELECT * FROM executions WHERE id=?', (execution_id,)).fetchone()
                if not row:
                    raise StateError('Execution already terminal or absent')
                if (actor.role == 'executor'
                        and (row['runner'] != actor.identity or not token
                             or not secrets.compare_digest(row['token_hash'], digest(token)))):
                    raise StateError('Runner identity/token mismatch')
                if row['status'] not in ('executing', 'unknown'):
                    if actor.role == 'executor' and row['status'] == outcome:
                        return {'status': outcome}
                    raise StateError('Execution already terminal or absent')
                if actor.role == 'human' and row['status'] != 'unknown':
                    raise StateError('Human reconciliation requires unknown outcome')
                connection.execute('UPDATE executions SET status=?,updated_at=? WHERE id=?',
                                   (outcome, utc_text(now), execution_id))
                connection.execute('UPDATE actions SET status=? WHERE id=?', (outcome, row['action_id']))
                self.audit(connection, now, actor.identity, 'execution.' + outcome, execution_id)
                return {'status': outcome}

    def recover_executions(self, *, now: dt.datetime | None = None) -> int:
        """Call at exclusive service startup, not while another writer is active."""
        now = clock(now)
        with self.transaction() as connection:
            rows = connection.execute("SELECT * FROM executions WHERE status='executing'").fetchall()
            for row in rows:
                connection.execute("UPDATE executions SET status='unknown',updated_at=? WHERE id=?",
                                   (utc_text(now), row['id']))
                connection.execute("UPDATE actions SET status='unknown' WHERE id=?", (row['action_id'],))
                self.audit(connection, now, 'platform-startup', 'execution.unknown', row['id'])
            return len(rows)

    def get_verification_binding(self, action_id: str, actor: Actor) -> dict[str, Any]:
        """Return the durable verification binding of one action, as JSON-safe defensive data.

        Delegation, and nothing more: `platform/verification_records.py` owns the gate, the shape and
        the meaning of every word (`bound`/`matched` with a digested origin, or `unbound` with one of the
        captured reasons, and `not-captured` for an action this build never captured). The binding is
        whatever the proposal was given at proposal time — never re-derived from the policy mounted
        today — so a restart or a changed policy cannot move what an old action meant.

        Raises:
            StateError: The actor may not read, `action_id` is not a canonical UUID, or no such action
                exists. An action that exists and was never captured is not an error: it answers
                `unbound`/`not-captured`.
        """
        from .verification_records import read_binding
        return read_binding(self, action_id, actor)

    def put_verification(self, record: dict[str, Any], actor: Actor, *,
                         now: dt.datetime | None = None) -> dict[str, Any]:
        """Accept one submitted observation and store the server's judgement of it.

        Returns ``{verification_id, created}``; `created` is False for the identical statement replayed,
        whose stored row is then unchanged. The caller cannot submit a verdict, a threshold or a reason:
        the record names an execution, a binding, a window, one of the three read-outcome words, at most
        one bounded receipt and at most 20 claimed rows, and `verification_records.write_record` derives
        `cleared`/`not_cleared`/`unknown` from the captured binding, the execution's own state and the
        server clock. Only a `producer` identity the currently mounted policy names as a verifier may
        write, and with no policy mounted every write is refused.

        Deliberately outside the `refusal` boundary that wraps the four action lifecycle methods: a
        verification submission is not an action attempt, so it writes no `action.refused` row. One
        accepted *first* write adds one `verification.recorded` audit row carrying only the id, the
        verdict and the reason; a duplicate or a conflict adds none.

        Raises:
            StateError: Authority, clock, shape, size, scope, the binding, the cap or a changed-content
                retry. Always one fixed sentence naming a field or a bound, never a value.
        """
        from .verification_records import write_record
        return write_record(self, record, actor, now=now)

    def get_verification(self, verification_id: str, actor: Actor) -> dict[str, Any] | None:
        """Return one stored verification document, or `None` when that id was never recorded.

        The whole readable record — the submitted statement, the captured origin it was scoped against,
        the verdict the server derived and who filed it — re-parsed from stored text into a fresh copy on
        every call. Nothing prunes or expires these rows, so a record whose evidence has long aged out
        still reads back exactly as it was judged at the time; re-grading history by a later clock is
        what this read exists to make impossible.

        Raises:
            StateError: The actor may not read, or `verification_id` is not a lowercase SHA-256 digest.
        """
        from .verification_records import read_record
        return read_record(self, verification_id, actor)

    def list_verifications(self, execution_id: str, actor: Actor) -> list[str]:
        """Return the verification ids one execution carries, lexical ascending, as a fresh list.

        Discovery only, and delegation: `platform/verification_reader.py` owns the read-only connection,
        the bounds and every refusal. The answer is id strings and nothing else — no payload, verdict,
        timestamp, claim, token or sample — so the ids discovered here are then read one at a time with
        `get_verification`. Order is lexical over validated ids and is deliberately not chronology.

        Called by nothing in this build; a later service may offload the synchronous read. It is not a
        `Store.records()` surface: these tables stay out of that allowlist, and this read takes no write
        lock, audits nothing and migrates nothing.

        Raises:
            StateError: The actor may not read, `execution_id` is not a canonical UUID, the execution is
                unknown, the database or the verification schema/index is unusable, or the stored ids or
                their count are not what this build's writer may have written. Never a partial list.
        """
        from .verification_reader import list_records
        return list_records(self, execution_id, actor)

    def status(self) -> dict[str, Any]:
        with self.transaction() as connection:
            return {'schema_version': VERSION,
                    'incidents': {row[0]: row[1] for row in connection.execute(
                        'SELECT status,count(*) FROM incidents GROUP BY status')},
                    'actions': {row[0]: row[1] for row in connection.execute(
                        'SELECT status,count(*) FROM actions GROUP BY status')},
                    'notifications': {row[0]: row[1] for row in connection.execute(
                        'SELECT status,count(*) FROM outbox GROUP BY status')}}

    def put_evidence(self, sample: dict[str, Any], actor: Actor, *,
                     now: dt.datetime | None = None) -> str:
        require(actor, 'producer')
        now = clock(now)
        if set(sample) != {'sample_id', 'observed_at', 'ok', 'value'} or not isinstance(sample['ok'], bool):
            raise StateError('Invalid evidence sample')
        label(sample['sample_id'])
        value = sample['value']
        if value is not None and not isinstance(value, (bool, int, float)):
            raise StateError('Only minimal numeric/boolean sample context is retained')
        if len(canonical(sample)) > 2048 or timestamp(sample['observed_at']) > now + dt.timedelta(seconds=60):
            raise StateError('Invalid bounded evidence sample')
        key = digest([actor.identity, sample['sample_id']])
        with self.transaction() as connection:
            old = connection.execute('SELECT fingerprint FROM evidence WHERE id=?', (key,)).fetchone()
            if old and old[0] != digest(sample):
                raise StateError('Evidence retry changed contents')
            connection.execute('INSERT OR IGNORE INTO evidence VALUES (?,?,?,?,?)',
                (key, actor.identity, canonical(sample), digest(sample),
                 utc_text(timestamp(sample['observed_at']) + dt.timedelta(days=15))))
        return key

    def get_evidence(self, source: str, sample_id: str, *,
                     now: dt.datetime | None = None) -> dict[str, Any]:
        with self.transaction() as connection:
            row = connection.execute('SELECT * FROM evidence WHERE id=?', (digest([source, sample_id]),)).fetchone()
            if not row:
                return {'status': 'unavailable'}
            if row['expires_at'] <= utc_text(clock(now)):
                return {'status': 'expired'}
            return {'status': 'available', 'sample': json.loads(row['payload']), 'expires_at': row['expires_at']}

    def records(self, table: str, limit: int = 100) -> list[dict[str, Any]]:
        if (table not in ('events', 'incidents', 'actions', 'executions', 'audit', 'outbox',
                          'notification_attempts')
                or not 1 <= limit <= 100):
            raise StateError('Invalid bounded record query')
        with self.transaction() as connection:
            rows = [dict(row) for row in connection.execute(
                f'SELECT * FROM {table} ORDER BY rowid DESC LIMIT ?', (limit,))]
            for row in rows:
                for secret in ('token_hash', 'claim_token', 'callback_token_hash'):
                    row.pop(secret, None)
            return rows

    def audit_page(self, *, limit: Any = None, category: Any = None,
                   snapshot: Any = None, before: Any = None) -> dict[str, Any]:
        """Return one bounded page of the audit history, newest first, from a read-only connection.

        Delegation, and nothing more: `platform/audit_reader.py` owns the bounds (page size, positions
        scanned per call, response bytes, per-row stored width), the closed `category` vocabulary, the
        `snapshot`/`before` cursor rules and the SQLite read itself. The defaults are named there and
        `None` means "take that unit's default" rather than a literal copied in here, so the numbers
        cannot drift between the two files.

        `records('audit')` above is unchanged and stays the capped single-window read; this is a second
        surface over the same table, not a replacement for it.

        Raises:
            StateError: A field is unknown, non-canonical, oversized, out of range, or a cursor naming
                only one of `snapshot`/`before`. Raised before the file is opened, and never audited:
                a bad read request is not a refused action attempt.
        """
        from .audit_reader import audit_page
        return audit_page(self.path, limit=limit, category=category, snapshot=snapshot, before=before)

    def backup(self, destination: Path | str) -> None:
        destination = Path(destination)
        with destination.open('xb'):
            pass
        with closing(sqlite3.connect(self.path)) as source, closing(sqlite3.connect(destination)) as target:
            source.backup(target)
            if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise StateError('Backup integrity failure')


def validate_event(event: dict[str, Any], now: dt.datetime) -> None:
    fields = {'schema_version', 'source', 'source_event_id', 'resource_id', 'observed_at', 'kind', 'severity',
              'data_class', 'evidence', 'rule_id', 'rule_version', 'window', 'condition', 'status'}
    if not isinstance(event, dict) or set(event) != fields or event['schema_version'] != 1:
        raise StateError('Invalid canonical event fields/version')
    if len(canonical(event).encode()) > 65536:
        raise StateError('Event exceeds 64 KiB')
    for name in ('source', 'source_event_id', 'rule_id', 'rule_version', 'condition'):
        label(event[name])
    if event['resource_id'] is not None:
        identifier(event['resource_id'])
    if (event['status'] not in ('firing', 'resolved', 'unknown')
            or event['kind'] not in EVENT_KINDS):
        raise StateError('Invalid event status/kind')
    if (event['severity'] not in ('info', 'warning', 'critical')
            or event['data_class'] not in ('public', 'internal', 'restricted')):
        raise StateError('Invalid severity/data classification')
    if not isinstance(event['window'], dict) or set(event['window']) != {'start', 'end'}:
        raise StateError('Invalid evaluation window')
    start, end = timestamp(event['window']['start']), timestamp(event['window']['end'])
    if not start < end <= now + dt.timedelta(seconds=60) or end - start > dt.timedelta(days=7):
        raise StateError('Invalid bounded evaluation window')
    if timestamp(event['observed_at']) > now + dt.timedelta(seconds=60):
        raise StateError('Future event')
    evidence = event['evidence']
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 20:
        raise StateError('Evidence references required')
    for item in evidence:
        if (not isinstance(item, dict)
                or set(item) != {'source', 'query_type', 'parameters', 'window', 'schema_version',
                                 'expires_at'}):
            raise StateError('Invalid evidence reference')
        label(item['source'])
        if (item['query_type'] not in ('gatus-result', 'observed-snapshot', 'metric-threshold',
                                       'source-heartbeat', 'sigma-count', 'sigma-source-coverage')
                or item['schema_version'] != 1):
            raise StateError('Unsupported evidence query')
        if item['window'] != event['window'] or timestamp(item['expires_at']) <= end:
            raise StateError('Invalid evidence retention/window')
        params = item['parameters']
        if not isinstance(params, dict) or not params or len(params) > 10:
            raise StateError('Invalid evidence parameters')
        for key, value in params.items():
            if (key not in ('snapshot_id', 'observation_id', 'endpoint', 'resource_id', 'sample_id',
                            'rule_id', 'artifact_sha256')
                    or not isinstance(value, str) or not 1 <= len(value) <= 256):
                raise StateError('Unapproved evidence parameter; no SQL or credentials')

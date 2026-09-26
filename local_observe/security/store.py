"""The owned ``security_events`` store: writes, the two reads, and the TTL drift check (security store).

One table, one policy, three things this module refuses to be:

* **not the operational record.** `local_observe/platform/state.py` stays authoritative for incidents
  (incident and action state), and every row written here is a *copy* of an event that already exists there, carrying
  the
  same identity pair. Nothing here reads this table to decide whether an incident is open.
* **not a second TTL mechanism.** The numbers are `ttl.py`'s; the DDL is rendered from them by
  `schema.py`; this module only ever *reads back* what the live table says (``system.tables``) and
  compares it. It never issues an ``ALTER``: a table that disagrees with the policy is a finding
  reported to an operator, not a thing a worker silently rewrites on boot.
* **not a second read path.** The three reads below go through
  `local_observe.store.backends.clickhouse.ClickHouse`, store facade's bounded client, so this package adds
  one write transport and no second query client, no second URL validation and no second idea of what
  a credential is.

Why a write transport exists at all, stated plainly for the reviewer: the read facade is read-only by
design (``readonly = 1``, ``allow_ddl = 0``, SELECT on three databases) and an analytical store must
be inserted into. `ClickHouseSecurityWriter` is therefore the smallest thing that can send a
statement, and the user behind it is necessarily *not* the read-only one — see
``components/data/store-signoz/clickhouse-users.d/CONTRACT.md`` ("A writer for the owned store"),
which states the grant as a proposal and not as a shipped privilege.

ClickHouse applies a ``TTL DELETE`` lazily, when parts merge. So `verify_ttl` proves the *declared*
TTL is the *deployed* one and reports how many rows are past due; the "aged rows actually disappear"
proof needs an ``OPTIMIZE``, which is a different privilege and an operator command
(``components/data/store-signoz/backup.md``, step 4a), not something this module does on a schedule.
"""
from __future__ import annotations

import datetime as dt
import json
import urllib.parse
import urllib.request
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from local_observe.http import NoRedirect, TransportError
from local_observe.log import get_logger
from local_observe.security.schema import (COLUMN_NAMES, FQ_TABLE, MAP_COLUMNS, SENSITIVE_COLUMNS,
                                          TIMESTAMP_COLUMNS, ddl_statements, insert_statement_prefix)
from local_observe.security.ttl import (DEFAULT_POLICY, TIERS, RetentionPolicy, TtlComparison, TtlRefused,
                                       compare, table_ttl_expression, tier_for)
from local_observe.store.client import LABEL, parse_ts, utc_text

log = get_logger(__name__)

EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
MAX_ROWS_PER_STATEMENT = 200
MAX_STATEMENT_BYTES = 1024 * 1024
# `state.validate_event` refuses an event whose canonical form is over 64 KiB, so a row's `raw`
# cannot legitimately exceed it; the bound is that ceiling and not a taste for small numbers.
MAX_RAW_BYTES = 65536
MAX_TEXT_BYTES = 1024
MAX_LABEL_ENTRIES = 16
# The write acknowledgement is ClickHouse's block-info line or an error page; 4 KiB is more than the
# first and less than anything worth holding in memory.
MAX_ACK_BYTES = 4096


class SecurityStoreRefused(ValueError):
    """A row or request this store will not accept; the reason names the rule, never the payload."""


class SecurityStoreUnavailable(SecurityStoreRefused):
    """The store could not be reached, or answered in a shape this module does not have."""


def _text(value: Any, name: str, *, maximum: int = MAX_TEXT_BYTES) -> str:
    """Return *value* as bounded single-line text, refusing anything else.

    Control characters are refused rather than stripped: a credential, a host path or a payload
    smuggled in as an embedded newline must not survive into a column this store then keeps for
    years. An empty string is legal for the optional columns and is what "this event had none" means,
    so a caller says so and this helper does not invent a value.
    """
    if not isinstance(value, str):
        raise SecurityStoreRefused(f'{name} must be text')
    if len(value.encode('utf-8')) > maximum:
        raise SecurityStoreRefused(f'{name} exceeds {maximum} bytes')
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SecurityStoreRefused(f'{name} holds a control character')
    return value


def _bounded_label(value: Any, name: str) -> str:
    """Return *value* if it is a bounded label (`store.client.LABEL`, the alphabet intake admits)."""
    if not isinstance(value, str) or not LABEL.fullmatch(value):
        raise SecurityStoreRefused(f'{name} must be 1-128 characters of [A-Za-z0-9_.:-]')
    return value


def nanos(value: Any, name: str) -> int:
    """Return one ISO-8601 stamp as whole nanoseconds since the epoch, in UTC.

    `store.client.parse_ts`'s naive-==-UTC rule is what makes the conversion name one instant on a
    host using a local timezone and a host set to UTC, and the integer form is what a ``DateTime64(9)`` column
    is fed (see `schema.TIMESTAMP_COLUMNS`): *text* is parsed under the server's session zone, which
    is how a five-year tier could quietly start five years earlier or later than its producer meant.
    """
    try:
        instant = parse_ts(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise SecurityStoreRefused(f'{name} must be an ISO-8601 timestamp') from exc
    delta = instant.astimezone(dt.timezone.utc) - EPOCH
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def epoch_text(value: Any) -> str:
    """Render one stored nanosecond value back into this repository's UTC text form."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SecurityStoreRefused('A stored timestamp must be non-negative whole nanoseconds')
    return utc_text(EPOCH + dt.timedelta(microseconds=value // 1000))


def cutoffs(policy: RetentionPolicy = DEFAULT_POLICY, *, now: dt.datetime | None = None) -> dict[str, int]:
    """Return the per-tier ``<tier>_cutoff_ns`` bindings `ClickHouseSecurityReader.expired` asks for.

    One place turns a tier length into an instant, shared by the real read and the in-memory backend,
    so the two cannot disagree about which rows are overdue. The number itself stays in `ttl.py`.
    """
    moment = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    return {f'{tier}_cutoff_ns': nanos(utc_text(moment - dt.timedelta(days=policy.days(tier))), 'cutoff')
            for tier in TIERS}


@dataclass(frozen=True)
class SecurityEvent:
    """One analytical copy of a canonical event, bound for the owned table.

    The field set is `schema.COLUMNS` minus ``retention_tier`` and minus ``received_at``: both are
    derived, never supplied. The tier comes from `ttl.tier_for` applied to the row's own severity, so
    nobody can place a row in the five-year tier by typing a word — which is the same reason the
    severity itself is checked against the three words intake admits.

    ``principal`` and ``raw`` are the columns that make this store the privacy boundary. They exist
    here and in no projection of it (`dualwrite.py`), and both are bounded: a payload that could hold
    a whole provider object is refused, because "the sensitive thing lives in exactly one place" needs
    that place to have walls.
    """

    ts: str
    source: str
    event_id: str
    rule_id: str
    rule_version: str
    kind: str
    status: str
    severity: str
    window_start: str
    window_end: str
    observed_at: str
    resource_id: str = ''
    artifact_sha256: str = ''
    principal: str = ''
    raw: str = ''
    labels: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Check every field at construction, so no half-built row reaches a statement."""
        _bounded_label(self.source, 'source')
        _bounded_label(self.event_id, 'event_id')
        _bounded_label(self.rule_id, 'rule_id')
        _bounded_label(self.rule_version, 'rule_version')
        _bounded_label(self.kind, 'kind')
        if self.kind != 'security':
            raise SecurityStoreRefused('this store holds security findings only; a coverage verdict is not one '
                                       'and belongs in the operational record alone')
        if self.status not in ('firing', 'resolved', 'unknown'):
            raise SecurityStoreRefused('status must be firing, resolved or unknown')
        if self.severity not in ('info', 'warning', 'critical'):
            raise SecurityStoreRefused('severity must be info, warning or critical')
        _text(self.resource_id, 'resource_id')
        _text(self.artifact_sha256, 'artifact_sha256', maximum=MAX_TEXT_BYTES)
        _text(self.principal, 'principal')
        _text(self.raw, 'raw', maximum=MAX_RAW_BYTES)
        for name in ('ts', 'window_start', 'window_end', 'observed_at'):
            nanos(getattr(self, name), name)
        if nanos(self.window_start, 'window_start') >= nanos(self.window_end, 'window_end'):
            raise SecurityStoreRefused('window_start must be before window_end')
        if len(self.labels) > MAX_LABEL_ENTRIES:
            raise SecurityStoreRefused(f'labels holds more than {MAX_LABEL_ENTRIES} entries')
        for key, value in self.labels.items():
            _bounded_label(key, 'labels key')
            _text(value, f'labels.{key}')

    @property
    def retention_tier(self) -> str:
        """The tier this row ages under — derived from severity, never set by a caller."""
        return tier_for(self.severity)

    def as_row(self, *, received_at: str) -> dict[str, Any]:
        """Return the ``JSONEachRow`` record for this event, keyed by `schema.COLUMNS` in order.

        Timestamps leave as whole nanoseconds (`nanos`) and the map as an object; every key is a
        column, so a statement built from this dict cannot name a column the table does not have.
        """
        row: dict[str, Any] = {}
        for name in COLUMN_NAMES:
            if name == 'retention_tier':
                row[name] = self.retention_tier
            elif name == 'received_at':
                row[name] = nanos(received_at, 'received_at')
            elif name in TIMESTAMP_COLUMNS:
                row[name] = nanos(getattr(self, name), name)
            elif name in MAP_COLUMNS:
                row[name] = dict(getattr(self, name))
            else:
                row[name] = _text(getattr(self, name), name,
                                  maximum=MAX_RAW_BYTES if name == 'raw' else MAX_TEXT_BYTES)
        return row


def sensitive_in(row: dict[str, Any]) -> set[str]:
    """Return which sensitive columns of *row* carry a value.

    The caller is a test, not the write path: the owned store is *meant* to hold these. Naming them
    here is what lets the projection's negative test iterate the product's own list instead of a copy
    written somewhere that can go stale.
    """
    return {name for name in SENSITIVE_COLUMNS if isinstance(row.get(name), str) and row[name]}


def insert_statement(rows: Sequence[dict[str, Any]]) -> str:
    """Return one bounded ``INSERT ... FORMAT JSONEachRow`` statement carrying *rows*.

    Values travel as JSON, which is what stops a payload breaking out of its quoted field: the
    statement carries no interpolated string. Two ceilings apply — the row count (a batch is one
    window's findings, not a backfill) and the byte size — and both are checked before anything is
    sent, so an oversized write is a refusal here rather than a server error mid-statement.
    """
    if not rows:
        raise SecurityStoreRefused('An INSERT with no rows is a bug, not a no-op')
    if len(rows) > MAX_ROWS_PER_STATEMENT:
        raise SecurityStoreRefused(f'one write may carry at most {MAX_ROWS_PER_STATEMENT} rows')
    payload = '\n'.join(json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                                   allow_nan=False) for row in rows)
    statement = f'{insert_statement_prefix()}\n{payload}'
    if len(statement.encode('utf-8')) > MAX_STATEMENT_BYTES:
        raise SecurityStoreRefused(f'the write statement exceeds {MAX_STATEMENT_BYTES} bytes')
    return statement


@dataclass(frozen=True)
class SchemaVerdict:
    """What ``ensure_schema`` sent, and whether the table agrees with the policy it was given.

    ``statements`` are both DDL statements, each ``IF NOT EXISTS``, so a re-run lands nothing and is
    safe at any time. The honest half is ``comparison``: ClickHouse leaves a pre-existing table
    exactly as it is, so applying a merged policy change over an old table answers ``drift`` (or
    ``no-ttl``) and the ``ALTER`` stays an operator decision. A run that printed "schema applied"
    while the table kept a different TTL is the exact failure this store exists to make visible.
    """

    statements: tuple[str, ...]
    comparison: TtlComparison

    def as_dict(self) -> dict[str, Any]:
        """Return the verdict as JSON-safe text: the statements and the TTL answer."""
        return {'statements': list(self.statements), 'ttl': self.comparison.as_dict()}


@dataclass(frozen=True)
class TtlVerdict:
    """What the live table's TTL says, and how many rows are already due to be gone.

    ``expired`` counts rows past their tier's deadline *at read time*. It is not a failure count:
    ClickHouse deletes lazily, so a non-zero number means the merge has not run, and ``status`` says
    whether the rule itself is right. Keeping the two apart is what stops a healthy store reading as
    broken and stops a store with no TTL at all reading as healthy. ``-1`` means the count could not be
    read, which is neither zero nor a number.
    """

    comparison: TtlComparison
    expired: int
    checked_at: str

    @property
    def status(self) -> str:
        """The one word a report or a coverage event repeats."""
        return self.comparison.status

    def as_dict(self) -> dict[str, Any]:
        """Return the verdict as JSON-safe text for a log line or a portal field."""
        return {'status': self.status, 'expired_rows': self.expired, 'checked_at': self.checked_at,
                'detail': self.comparison.detail, 'ttl': self.comparison.as_dict()}


class ClickHouseSecurityWriter:
    """Send one DDL or INSERT statement to the owned store, and nothing else.

    Deliberately the mirror of store facade's ``ClickHouse`` client *without* the read-only settings, because
    that absence is the difference between the two jobs: this one must be able to write, so the
    credential behind it is a different user by necessity. The endpoint rules are the same ones
    (HTTPS unless ``allow_http`` is set, no embedded credentials, no query, no fragment, no proxy, no
    redirect), the acknowledgement is read at 4 KiB, the timeout is 10 seconds, and the error that
    reaches the caller is one fixed sentence carrying neither the credential nor the payload.
    """

    def __init__(self, url: str, user: str, password: str, *, allow_http: bool = False) -> None:
        """Bind to one endpoint and credential pair, validated before anything is stored."""
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme not in (('https', 'http') if allow_http else ('https',))
                or not parsed.hostname or parsed.username or parsed.password or parsed.query
                or parsed.fragment):
            raise SecurityStoreRefused('Explicit trusted ClickHouse endpoint required')
        if not isinstance(user, str) or not LABEL.fullmatch(user):
            raise SecurityStoreRefused('The write user must be a bounded name')
        if not isinstance(password, str) or not password:
            raise SecurityStoreRefused('The write credential must not be empty')
        self.url, self.user, self.password = url, user, password

    def execute(self, statement: str) -> str:
        """POST one statement built by this package and return the server's acknowledgement text.

        The statement is never caller text: it comes from `schema.ddl_statements` or
        `insert_statement`, both assembled from this repository's constants. The acknowledgement is
        read and returned but never logged — a successful INSERT answers with block info and a failure
        answers with a page that may quote the statement, and neither belongs in a log line.
        """
        if not isinstance(statement, str) or not statement:
            raise SecurityStoreRefused('A write statement is required')
        request = urllib.request.Request(
            self.url, data=statement.encode('utf-8'), method='POST',
            headers={'X-ClickHouse-User': self.user, 'X-ClickHouse-Key': self.password})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            with opener.open(request, timeout=10) as response:
                body = response.read(MAX_ACK_BYTES + 1)
                if len(body) > MAX_ACK_BYTES:
                    raise SecurityStoreUnavailable('Oversized write acknowledgement')
                return body.decode('utf-8', 'replace')
        except SecurityStoreUnavailable:
            log.warning('Security store write refused', extra={'error_class': 'SecurityStoreUnavailable'})
            raise
        except Exception as exc:
            # One fixed sentence, on purpose: the statement may hold a `raw` payload and the request
            # carries the credential, so neither may reach a log line or the caller's error text.
            log.warning('Security store write unavailable', extra={'error_class': type(exc).__name__})
            raise SecurityStoreUnavailable('The security_events store refused or did not answer the write') \
                from None


class ClickHouseSecurityReader:
    """The store's three named reads, run on store facade's bounded read-only client.

    No statement is built from caller text and there is no fourth read: the TTL expression, the
    distinct event count, and the count of rows past their tier deadline. All three answer a single
    aggregate row, so they go through ``ClickHouse.query``, which pins ``readonly = 1``, the seven read
    bounds and the 64 KiB response cap — the same profile every other platform read already uses.

    TTL metadata comes from the documented ``system.tables.create_table_query`` column. The parser
    accepts the owned two-tier policy and refuses other expressions. Deployment acceptance still
    requires a read against the pinned server using the proposed reader grant.
    Metadata reference: https://clickhouse.com/docs/reference/system-tables/tables
    """

    TTL_SQL = ('SELECT count() AS table_count, any(create_table_query) AS create_table_query '
               'FROM system.tables WHERE database = {database:String} '
               'AND name = {table:String} FORMAT JSON')
    EVENTS_SQL = f'SELECT uniqExact(source, event_id) AS row_count FROM {FQ_TABLE} FORMAT JSON'
    EXPIRED_SQL = (f'SELECT count() AS row_count FROM {FQ_TABLE} WHERE '
                   "(retention_tier = 'critical' AND ts < fromUnixTimestamp64Nano({critical_cutoff_ns:UInt64})) "
                   "OR (retention_tier = 'routine' AND ts < fromUnixTimestamp64Nano({routine_cutoff_ns:UInt64})) "
                   'FORMAT JSON')

    def __init__(self, client: Any) -> None:
        """Bind to one already-validated read-only query client."""
        if not hasattr(client, 'query'):
            raise SecurityStoreRefused('The security reader needs the bounded ClickHouse query client')
        self.client = client

    def live_ttl_expression(self) -> str:
        """Read the table TTL; distinguish absent, malformed and unreachable metadata."""
        database, table = FQ_TABLE.split('.')
        row = self._aggregate(self.TTL_SQL, {'database': database, 'table': table}, 'table_count')
        count = row['table_count']
        if type(count) not in (int, str) or count not in (0, 1, '0', '1'):
            raise SecurityStoreUnavailable('The security_events table metadata has an invalid table count')
        if count in (0, '0'):
            raise SecurityStoreUnavailable('The security_events table is absent')
        try:
            return table_ttl_expression(row.get('create_table_query'))
        except TtlRefused as exc:
            raise SecurityStoreUnavailable(str(exc)) from None

    def count(self) -> int:
        """Return how many distinct events the store holds.

        ``uniqExact(source, event_id)`` and not ``count()``: the table is a ``ReplacingMergeTree``
        whose dedupe runs when parts merge, so a raw ``count()`` would double-count a retried
        evaluation until the merge happened and the number would depend on merge timing. Counting the
        identity pair is the question anybody is actually asking — how many findings exist — and it
        answers the same before and after a merge.
        """
        return self._scalar(self.EVENTS_SQL, {})

    def expired(self, cutoff: dict[str, int]) -> int:
        """Return how many rows sit past their tier's deadline (see `TtlVerdict`)."""
        return self._scalar(self.EXPIRED_SQL, cutoff)

    def _aggregate(self, sql: str, parameters: dict[str, Any], field_name: str) -> dict[str, Any]:
        """Run one reviewed aggregate and return its single row, refusing a wrong shape."""
        try:
            row = self.client.query(sql, parameters)
        except (TransportError, ValueError, KeyError, TypeError) as exc:
            log.debug('Security store aggregate read failed', extra={'error_class': type(exc).__name__})
            raise SecurityStoreUnavailable('The security_events store could not be read') from None
        if not isinstance(row, dict) or field_name not in row:
            raise SecurityStoreUnavailable('The security_events store answered an unexpected shape')
        return row

    def _scalar(self, sql: str, parameters: dict[str, Any]) -> int:
        """Read one aggregate's single number, refusing a non-number and a negative count."""
        value = self._aggregate(sql, parameters, 'row_count')['row_count']
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise SecurityStoreUnavailable('The security_events store answered a non-number')
        try:
            number = int(float(value))
        except ValueError:
            raise SecurityStoreUnavailable('The security_events store answered an unreadable count') from None
        if number < 0:
            raise SecurityStoreUnavailable('The security_events store answered a negative count')
        return number


class SecurityEventStore:
    """The owned store's surface: apply the schema, write events, check what the table obeys.

    Both transports are injected — a writer that can send a statement and a reader that can answer the
    three named aggregates — which is what lets this whole surface run under the unit tier with no
    server, and lets a deployment put a read-only credential behind the reader and a writer credential
    behind the writer without this class knowing, or caring, which is which.
    """

    def __init__(self, *, writer: Any, reader: Any,
                 policy: RetentionPolicy = DEFAULT_POLICY) -> None:
        """Bind the store to one writer, one reader and one policy."""
        if not hasattr(writer, 'execute'):
            raise SecurityStoreRefused('The store needs a writer that can execute a statement')
        if not hasattr(reader, 'live_ttl_expression'):
            raise SecurityStoreRefused('The store needs a reader that can report a live TTL expression')
        self.writer, self.reader, self.policy = writer, reader, policy

    def ensure_schema(self) -> SchemaVerdict:
        """Apply the owned DDL (idempotent) and then read the table's TTL back.

        Run by the operator's CLI and never by a worker on boot: a process that provisions its own
        schema is a process whose schema nobody reviewed, and this table's TTL is a retention promise
        rather than an implementation detail.
        """
        statements = ddl_statements(self.policy)
        for statement in statements:
            self.writer.execute(statement)
        return SchemaVerdict(statements=tuple(statements),
                             comparison=self._ttl_comparison())

    def _ttl_comparison(self) -> TtlComparison:
        """Keep metadata failures visible in the comparison verdict."""
        try:
            return compare(self.reader.live_ttl_expression(), self.policy)
        except SecurityStoreUnavailable as exc:
            return TtlComparison(status='unreadable', declared=self.policy, live=None, detail=str(exc))

    def write(self, events: Iterable[SecurityEvent], *, received_at: str | None = None) -> int:
        """Insert a batch of analytical rows and return how many were sent.

        Every row is validated by `SecurityEvent.__post_init__` and the whole statement is built
        before the first byte is sent, so one malformed event fails the batch visibly instead of being
        dropped beside its neighbours. A repeated identity inside one batch is refused: the table would
        keep one row and this call would have reported two, which is the double-count the stable event
        id exists to prevent. A transport failure raises `SecurityStoreUnavailable` — the operational
        record is already durable, so a copy either landed or is retried, and a retry is one row.
        """
        stamps = received_at or utc_text(dt.datetime.now(dt.timezone.utc))
        rows = [event.as_row(received_at=stamps) for event in events]
        if not rows:
            return 0
        identities = {(row['source'], row['event_id']) for row in rows}
        if len(identities) != len(rows):
            raise SecurityStoreRefused('one batch carries a repeated (source, event_id); the table keeps one '
                                       'row, so the write count would be a lie')
        self.writer.execute(insert_statement(rows))
        return len(rows)

    def count(self) -> int:
        """How many distinct findings the store holds (see `ClickHouseSecurityReader.count`)."""
        return self.reader.count()

    def verify_ttl(self, *, now: dt.datetime | None = None) -> TtlVerdict:
        """Compare the live table's TTL with the policy, and count the rows already due to go.

        The check reports a status word instead of
        raising: a caller that cannot read the table gets ``unreadable``, which is a visible state and
        not the nothing of a dropped check. ``now`` is injected by tests and defaults to the real
        clock; it moves only the *expired* count, never the comparison, because a TTL string does not
        age.
        """
        checked_at = utc_text((now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc))
        comparison = self._ttl_comparison()
        try:
            expired = self.reader.expired(cutoffs(self.policy, now=now))
        except SecurityStoreUnavailable:
            expired = -1
        return TtlVerdict(comparison=comparison, expired=expired, checked_at=checked_at)

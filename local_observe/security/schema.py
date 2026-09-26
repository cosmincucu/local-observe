"""The owned ``security_events`` DDL, rendered from the TTL policy and from nothing else.

A dedicated database with an owned table — not a label inside SigNoz's managed schema (security store, port of
`legacy:aiops/security/schema.py`). That distinction is the reason this module exists:

* SigNoz retention is **per signal**, so one TTL covers every row of ``signoz_logs``. The store needs
  two tiers over one table (see `ttl.py`), which a per-signal setting cannot express.
* SigNoz upgrade migrations rewrite their managed tables, so a hand-ALTER inside ``signoz_*`` survives
  until the next version does. An owned table is altered by this repository or not at all.
* One table is one privacy boundary: the sensitive payload columns (`principal`, `raw`) live here and
  nowhere else, so "where is the sensitive copy" has one answer.

Two properties are load-bearing and both are tested rather than asserted. The ``TTL`` clause is
rendered **from** `ttl.RetentionPolicy`, so a table cannot be created with a retention the policy does
not declare. And the ``ORDER BY`` key is the event's identity pair — the same pair
``platform/state.py`` enforces as ``events UNIQUE (source, source_event_id)`` — so the analytical copy
of a retried evaluation is the same row, not a second record an incident count would double (the
sentence `docs/CONTRACTS.md` §4 says about stable event ids).

No statement here is ever applied by a running worker: `ddl_statements` is reached by
``local_observe.security.cli apply-schema``, run by the operator, and by nothing else (incident and action state: a
worker
that provisions its own schema is a worker that silently changes the store).
"""
from __future__ import annotations

import re

from local_observe.security.ttl import RetentionPolicy, build_ttl_clause

DATABASE = 'security_events'
TABLE = 'events'
FQ_TABLE = f'{DATABASE}.{TABLE}'

CREATE_DATABASE_SQL = f'CREATE DATABASE IF NOT EXISTS {DATABASE}'

# One list, two readers. Each entry is ``(column, ClickHouse type)``: `create_table_sql` renders the
# definitions in order and `store.py` names exactly these columns in its INSERT, so a column added
# here lands in both halves together and an INSERT can never quietly gain a column the table lacks —
# nor lose one into a `NOT NULL` it did not ask about.
COLUMNS: tuple[tuple[str, str], ...] = (
    ('ts', "DateTime64(9, 'UTC')"),               # the instant the row ages from: the event's observed_at
    ('source', 'LowCardinality(String)'),          # the producer identity, half of the event's key
    ('event_id', 'String'),                       # the operational event's source_event_id, verbatim
    ('resource_id', "LowCardinality(String)"),     # the declared UUID, or '' when the source was unresolved
    ('rule_id', 'String'),                        # the canonical event's rule_id (sigma.<uuid> for a Sigma finding)
    ('rule_version', 'LowCardinality(String)'),    # the compiler's rule digest, so a rule edit is visible
    ('kind', 'LowCardinality(String)'),            # the canonical kind: `security` for a matched rule
    ('status', 'LowCardinality(String)'),          # firing | resolved | unknown, as intake saw it
    ('severity', 'LowCardinality(String)'),         # info | warning | critical, as the crosswalk chose it
    ('retention_tier', 'LowCardinality(String)'),   # THE TTL gate: `critical` | `routine` (ttl.py)
    ('window_start', "DateTime64(9, 'UTC')"),      # the evaluation window the verdict was made over
    ('window_end', "DateTime64(9, 'UTC')"),
    ('observed_at', "DateTime64(9, 'UTC')"),
    ('artifact_sha256', 'String'),                  # the compiled artifact the SQL came from, '' when not one
    ('principal', 'String'),                        # PRIVACY-SENSITIVE: who/what the event is about; owned store only
    ('raw', 'String'),                              # PRIVACY-SENSITIVE: the payload behind the verdict; owned only
    ('labels', 'Map(String, String)'),              # bounded extras; never a credential, never a host path
    ('received_at', "DateTime64(9, 'UTC')"),        # when this row was written, distinct from the event's own stamp
)

# The columns ClickHouse types as DateTime64: the write path renders these as whole nanoseconds and
# nothing else, because a *text* date is parsed in the session's zone while an integer for a
# `DateTime64(9, 'UTC')` column is nanoseconds since the epoch and means one instant on every server.
TIMESTAMP_COLUMNS = frozenset(name for name, kind in COLUMNS if kind.startswith('DateTime64'))
MAP_COLUMNS = frozenset(name for name, kind in COLUMNS if kind.startswith('Map'))
COLUMN_NAMES: tuple[str, ...] = tuple(name for name, _ in COLUMNS)

# The privacy boundary, spelled as a tuple so the dual-write's negative test iterates the real list
# instead of a copy that can go stale: a projection may not carry any of these, in any shape.
SENSITIVE_COLUMNS = frozenset({'principal', 'raw'})

# A single-host store (the reference deployment runs one ClickHouse, and so does the estate), so no
# ON CLUSTER anywhere here on purpose: an owned table must not be entangled with SigNoz's
# distributed/cluster machinery, and a cluster edition that needs it is a deliberate edit to this
# constant with its own review.
CREATE_TABLE_TEMPLATE = """CREATE TABLE IF NOT EXISTS {fq_table}
(
{columns}
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (source, event_id)
{ttl_clause}
SETTINGS index_granularity = 8192"""

# This extraction is only for DDL rendered by this module and consumed by the in-memory backend.
# The live reader instead uses ttl.table_ttl_expression on system.tables.create_table_query;
# both extracted clauses feed the same strict policy parser.
_TTL_BODY = re.compile(r'\bTTL (.+?)\nSETTINGS\b', re.DOTALL)


def create_table_sql(policy: RetentionPolicy | None = None) -> str:
    """Return the ``CREATE TABLE`` for *policy*, its TTL clause rendered by `ttl.build_ttl_clause`.

    Pure and deterministic: the same policy renders the same text, so a test can pin the whole
    statement and the apply path cannot produce a table that disagrees with the policy it was given.
    The default policy is `ttl.DEFAULT_POLICY` — a caller that passes ``None`` gets the shipped
    numbers, never an empty TTL.
    """
    resolved = policy or RetentionPolicy()
    return CREATE_TABLE_TEMPLATE.format(
        fq_table=FQ_TABLE,
        columns=',\n'.join(f'    {name} {kind}' for name, kind in COLUMNS),
        ttl_clause=build_ttl_clause(resolved))


def ddl_statements(policy: RetentionPolicy | None = None) -> list[str]:
    """The ordered statements ``ensure_schema`` applies: the database, then the owned table.

    Spelled as two statements so a failure names which half did not land, and so a caller may report
    "the database already existed" separately from "the table already existed" — which is the
    distinction that matters when a table exists with a *different* TTL (drift, not creation).
    """
    return [CREATE_DATABASE_SQL, create_table_sql(policy)]


def ttl_from_ddl(statement: str) -> str:
    """Return the TTL body inside DDL this module rendered, or ``''`` when it carries none.

    The answer keeps `ttl.build_ttl_clause`'s spelling (`INTERVAL n DAY`), while a live table answers
    `toIntervalDay(n)`; `ttl.parse_ttl_expression` reads both, which is what lets the in-memory
    backend and a real server be checked by one comparison.
    """
    if not isinstance(statement, str):
        raise ValueError('A DDL statement is text')
    match = _TTL_BODY.search(statement)
    return match.group(1).strip() if match else ''


def insert_statement_prefix() -> str:
    """Return the ``INSERT INTO ... (columns) FORMAT`` head every write uses.

    A named column list rather than ``INSERT INTO t FORMAT`` positional form: with the column names
    present, a table altered to add a column still receives the columns this code knows about, while
    the positional form would silently shift every value one column right.
    """
    return f'INSERT INTO {FQ_TABLE} ({", ".join(COLUMN_NAMES)}) FORMAT JSONEachRow'

"""The in-memory ``security_events`` backend: every rule of the owned store, no server (tests, demo).

The twin of ``local_observe/store/backends/memory.py``, and here for the same reason: the properties
this card promises — re-applying the DDL is a no-op, a retry is one row, a policy change over an old
table is *drift* and not a silent pass — have to be proven without a ClickHouse to argue with, and a
test that mocks the answer proves nothing about the rules.

It implements the two seams `store.py` uses (a writer's ``execute(statement)`` and the reader's three
named reads) over one dict, and models exactly three pieces of server behaviour:

* **``IF NOT EXISTS`` really does nothing on the second run.** The DDL is parsed and applied once; a
  re-apply leaves the recorded TTL alone. That is what makes `SecurityEventStore.ensure_schema` able
  to report drift instead of success: apply a 90-day policy, then apply a 30-day one, and the
  "live" expression still says 90 because that is what a real server would still say.
* **the recorded TTL is the DDL's own text**, recovered by `schema.ttl_from_ddl` — so the live-vs-
  declared comparison runs over the same string a server would render (in the interval spelling it
  accepts), not over a policy copied into a fixture.
* **the ``ORDER BY`` pair is the row key.** A write of an existing ``(source, event_id)`` replaces the
  row, which is ``ReplacingMergeTree``'s steady state. The difference must stay visible: a real server
  keeps both copies in different parts until a merge collapses them, which is why the production
  ``count()`` is ``uniqExact(source, event_id)`` and not ``count()`` (see
  `ClickHouseSecurityReader.count`). This backend collapses immediately and is therefore the
  *stronger* behaviour; a test that needs the un-merged shape needs a server, not this file.

Nothing here reaches a network or a file, and nothing here relaxes a check: a statement it does not
recognise is a refusal, never a shrug, so a future write path cannot quietly stop being modelled.
"""
from __future__ import annotations

import json
from typing import Any

from local_observe.security.schema import COLUMN_NAMES, FQ_TABLE, insert_statement_prefix, ttl_from_ddl
from local_observe.security.store import SecurityStoreRefused
from local_observe.security.ttl import TIERS


class InMemorySecurityStore:
    """An inspectable owned store, written and read under `store.py`'s own rules.

    Use it as both transports of one `SecurityEventStore::

        backend = InMemorySecurityStore()
        store = SecurityEventStore(writer=backend, reader=backend)

    and read the result through ``rows`` / ``statements`` / ``live_ttl_expression``.
    """

    def __init__(self) -> None:
        """Start with no database, no table and no rows, exactly like a fresh ClickHouse."""
        self.database = False
        self.table = False
        self.ttl_expression = ''
        self._rows: dict[tuple[str, str], dict[str, Any]] = {}
        self.statements: list[str] = []
        self.reads = 0
        self.reapplied = 0

    # ── the writer seam ───────────────────────────────────────────────────────
    def execute(self, statement: str) -> str:
        """Apply one DDL or INSERT statement built by this package, and record that it ran.

        Returns '' because there is no acknowledgement text to give. An unrecognised statement is a
        refusal: the point of this backend is that it models the real one, and silently accepting a
        statement it does not understand is how a test starts passing for a write that would fail.
        """
        if not isinstance(statement, str) or not statement:
            raise SecurityStoreRefused('A write statement is required')
        self.statements.append(statement)
        if statement == f'CREATE DATABASE IF NOT EXISTS {FQ_TABLE.split(".")[0]}':
            self.database = True
            return ''
        if statement.startswith('CREATE TABLE'):
            return self._create_table(statement)
        if statement.startswith(insert_statement_prefix()):
            return self._insert(statement)
        raise SecurityStoreRefused(f'the in-memory store does not model this statement: '
                                   f'{statement.splitlines()[0][:80]}')

    def _create_table(self, statement: str) -> str:
        """Apply ``CREATE TABLE IF NOT EXISTS`` once, and record nothing on every later run.

        The no-op is the behaviour being modelled, and it is counted (``reapplied``) rather than
        hidden, so a test can tell "the DDL is idempotent" apart from "the DDL never ran".
        """
        head = statement.split('\n', 1)[0]
        if head != f'CREATE TABLE IF NOT EXISTS {FQ_TABLE}':
            raise SecurityStoreRefused('the in-memory store models one table, the owned one')
        ttl = ttl_from_ddl(statement)
        if not ttl:
            raise SecurityStoreRefused('the owned table must carry a TTL clause; a table with no expiry '
                                       'is not this store')
        if self.table:
            self.reapplied += 1
            return ''
        self.table = True
        self.ttl_expression = ttl
        return ''

    def _insert(self, statement: str) -> str:
        """Parse the ``JSONEachRow`` payload and key each row by the table's ``ORDER BY`` pair."""
        if not self.table:
            raise SecurityStoreRefused('the owned table does not exist; apply the schema before writing')
        payload = statement[len(insert_statement_prefix()):].strip()
        if not payload:
            raise SecurityStoreRefused('An INSERT with no rows is a bug, not a no-op')
        for line in payload.splitlines():
            row = json.loads(line)
            if not isinstance(row, dict) or set(row) != set(COLUMN_NAMES):
                raise SecurityStoreRefused('a written row must carry exactly the owned table columns')
            key = (str(row['source']), str(row['event_id']))
            self._rows[key] = row
        return ''

    # ── the reader seam ───────────────────────────────────────────────────────
    def live_ttl_expression(self) -> str:
        """The TTL text the applied DDL carried, or ``''`` when no table exists (as a server would)."""
        self.reads += 1
        return self.ttl_expression if self.table else ''

    def count(self) -> int:
        """Distinct ``(source, event_id)`` rows held — the same question the production read asks."""
        self.reads += 1
        return len(self._rows)

    def expired(self, cutoff: dict[str, int]) -> int:
        """Rows stamped before their tier's cutoff, using the shared `store.cutoffs` arithmetic."""
        self.reads += 1
        missing = [f'{tier}_cutoff_ns' for tier in TIERS if f'{tier}_cutoff_ns' not in cutoff]
        if missing:
            raise SecurityStoreRefused(f'the expired read names no cutoff for {", ".join(missing)}')
        return sum(1 for row in self._rows.values() if row['ts'] < cutoff[f"{row['retention_tier']}_cutoff_ns"])

    # ── the inspection surface tests read ─────────────────────────────────────
    @property
    def rows(self) -> list[dict[str, Any]]:
        """Every stored row, in write order, as the ``JSONEachRow`` records they were written from."""
        return list(self._rows.values())

    def row(self, source: str, event_id: str) -> dict[str, Any] | None:
        """One stored row by its identity pair, or ``None`` when the store has never seen it."""
        return self._rows.get((source, event_id))

"""The owned ``security_events`` store — long-retention analytical security events (security store).

One package, three properties, all of them testable rather than documented hopes:

* **the TTL numbers exist in exactly one module.** `ttl.py` holds them; `schema.py` renders its DDL
  *from* that policy; `store.SecurityEventStore.verify_ttl` extracts the table TTL from
  ``system.tables.create_table_query`` and compares. A table that disagrees with the policy is reported
  (``drift``, ``no-ttl``, ``unreadable``), never a quiet difference. These are **not** telemetry retention's telemetry
  retention numbers — see the one line in `ttl.py` that says why — and a table's tier is derived from
  an event's severity by that same module, so a row cannot be promoted to the long tier by whoever is
  writing it.
* **the sensitive payload lives in exactly one place.** `principal` and `raw` are columns of the owned
  table and appear in no projection of it (`dualwrite.short_ttl_projection`), which is what makes the
  two-tier design mean anything: a short-TTL dashboard copy of the payload would put the long tier out
  of a job.
* **backup coverage is verified, not assumed.** `backup.coverage` asks whether the data directory the
  store's backup unit copies actually contains the table, and
  ``components/data/store-signoz/backup.md`` (step 4a) states the answer as of this writing with the
  command that re-derives it.

**What this package is not.** Not the operational record: ``platform/state.py`` decides what is open
(incident and action state), and every row here is a copy carrying that record's own ``(source, source_event_id)``
identity
so a retry lands on one row instead of two (`docs/CONTRACTS.md` §4). Not a second read path: the
store's three aggregates run on store facade's bounded client. Not self-provisioning: the DDL is applied by
an operator through ``local_observe.security.cli``, never by a worker on boot, and no code here issues
an ``ALTER``.

**Status, stated plainly.** Nothing in this package has been executed against a live ClickHouse, and
no host has the writer user it needs — the grant is proposed in
``components/data/store-signoz/clickhouse-users.d/CONTRACT.md`` and awaits a reviewer, which is why
``sigma_runner``'s write hook stays off until a credential is configured. The in-memory backend
(`memory.py`) is what the unit tier proves the rules against.
"""

# Upgrade

Component `query-adapter`. Nothing here upgrades: the pin rule in `docs/COMPONENTS.md`-adjacent estate
policy — a pin moves on a branch carrying a reason and a rollback line, and is seen running against its
real consumers before its PR merges — applies with full force, and this component is where a store
upgrade *shows up* rather than where it is decided.

## What an upgrade can break here, and how loudly

| Change in the candidate | First symptom | Where the fix belongs |
| :-- | :-- | :-- |
| A SigNoz release renames a table (`distributed_logs_v2`, `distributed_samples_v4`, `distributed_time_series_v4`, `distributed_signoz_index_v3`) | Every read of that signal answers `unavailable`, coverage events fire. A rename **inside** one of the three granted databases is silent-but-safe: the grants are per database. A signal moving to a **new database** is the one quiet failure: the user can read nothing and every query still "works" | `QUERY_SQL` in `local_observe/store/backends/clickhouse.py`, the table list in `versions.json` below, and the `GRANT` lines in **both** `lo-query.xml` and `lo-read.xml` — one commit, or the read works in a test and returns nothing in production |
| A column changes type, or `Map(String, String)` renders differently in `FORMAT JSON` | `_map`/`_number`/`_instant` refuse the row; the read becomes `unavailable` with one log line naming `ValueError`. Never a coerced value | the row mappers in that backend module, plus `tests/test_store_facade.py`'s quoted-integer and both-map-shapes cases |
| A ClickHouse release stops merging `users.d` | `lo-read` (then `lo-query`) is undefined; the reader refuses to authenticate; loudly | the store component, not this one |
| The platform starts sending a setting the profiles do not mark `changeable_in_readonly` | every read fails with a settings-constraint error — which reads like a store outage | add the name to the `constraints` block of **both** fragments in the same commit that adds it to the client (`clickhouse-users.d/upgrade.md` item 3) |
| `MAX_ROWS` moves (a wider analysis page) | `tests/test_query_adapter.py::AnalysisProfile::test_the_row_ceiling_is_the_transport_bound_not_a_number_invented_here` fails: the profile says 2 000 and the code says something else | `versions.json`'s `row_caps`, `store/client.py:MAX_ROWS` and `lo-read.xml`, together — the test is the mechanism that keeps the three honest |
| The Sigma mapping identity changes (`signoz-logs-v2-linux-process-v1`) | `sigma_runner.artifact()` refuses every artifact with "Unsupported compiled mapping"; the runner stops rather than reads the wrong columns | the compiler, the artifacts, and the `mapping_identity` field below in one change |

## The rehearsal, in order

1. Read the current tuple: [`versions.json`](versions.json) → the keys it names in
   `components/data/store-signoz/versions.json` and `image-lock.json`. Do not restate a digest here.
2. Bring up the candidate in a **separate Compose project** with its own volumes (never the reference
   deployment's): `examples/full` on the candidate pins, per its README.
3. Run [`conformance.md`](conformance.md) — Recipe A (both users' privileges, including the row cap),
   Recipe B (the three reads, truncation, the empty-series case), Recipe C steps 1–4 (evidence stays
   queryable). Record every line `pass`/`fail`/`not-run`.
4. Confirm the compiled artifacts still match: recompile one Sigma rule against the candidate, and
   check its `FROM` clause's database against the `GRANT` lines in both fragments. This is the only
   step above that catches the quiet failure in the table.
5. Only then move the pin, in a commit that names the reason, the rollback line (the previous digest)
   and the evidence file. The merge authorises promotion; it does not close the item.

## Backward compatibility of the envelope

`query.py`'s eight keys are the `docs/CONTRACTS.md` §2 field list, and they are a published shape the
moment RCA, MCP and the portal read them. A consumer must not have to handle two shapes: adding a key
is a contract change (it moves §2, which is event intake's file this wave), and changing `rows` from
JSON-safe mappings back to dataclass instances would break every bundle that serialises an envelope.
`error`'s two prefixes are stable words — `refused:` / `failed:` / `unavailable:` — because a producer
that branches on them is how "absent data" and "absent records" stay separate verdicts downstream;
renaming one moves this file, `conformance.md`'s tables and the tests that assert them.

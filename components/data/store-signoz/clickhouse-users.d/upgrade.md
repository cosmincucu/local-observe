# Upgrade

A ClickHouse or SigNoz pin move (`components/data/store-signoz/versions.json` and `image-lock.json`)
re-opens three questions about this directory. All three are answered by running `conformance.md`
against the candidate image **before** the pin is promoted, not after:

1. **Does the pinned image still load `users.d/`?** Every release so far merges the per-user fragments
   in this directory, and the store already depends on it for `clickhouse-query-mem.xml`. A release
   that changed the users config path or stopped merging `users.d` would leave `lo-query` undefined,
   which fails loudly at the Sigma runner rather than quietly widening it.
2. **Do the grants still cover the signal tables?** A SigNoz release can rename a table
   (`distributed_logs_v2` and friends) or move a signal into a new database. Grants here are per
   database, so a rename inside a database is free and a new database is not: the runner then reads
   zero rows for its window and reports nothing, which is the one failure mode of this list that is
   **not** loud. Check the compiled artifact's `FROM` clause against the databases named in
   `lo-query.xml` on every SigNoz upgrade.
3. **Does the runner still send the same settings?** `lo-query`'s profile declares the seven bounds
   `local_observe/platform/sigma_runner.py` posts, each marked `changeable_in_readonly`, because under
   `readonly = 1` ClickHouse refuses a client setting change unless it is marked that way. If the
   runner starts sending a setting that is not in that list, its queries fail with a settings-constraint
   error; add the name to the `constraints` block in the same change that adds it to the runner.

The credential form is the last thing to re-check: `<password incl="…"/>` (plaintext method) is what
authenticates an `X-ClickHouse-Key` header on this deployment's plaintext HTTP project network. A
release that refused plaintext-method authentication over an insecure interface would break the runner
at login, not silently.

## `lo-read` (query adapter) — the same three questions, plus one of its own

Every item above applies to `lo-read.xml` unchanged: it is a `users.d` fragment, it names the same
three databases, and its profile declares the same seven bounds the platform's clients post
(`local_observe/store/backends/clickhouse.py` sends them on every request, and
`local_observe/platform/query.py` builds that client and no other).

The fourth question is the row ceiling. `max_result_rows = 2000` in that file is pinned to
`local_observe/store/client.py:MAX_ROWS`, and `tests/test_query_adapter.py::AnalysisProfile` is what
holds the two numbers together; a release that changes either side changes both in one commit or the
test says so. A SigNoz or ClickHouse upgrade that changes how `FORMAT JSON` sizes a row does not move
the number, but it can move where the read actually stops — `max_bytes_to_read` (64 MiB) and the
client's 64 KiB response cap are the two limits a fatter row can hit first, and both fail closed
rather than truncating.

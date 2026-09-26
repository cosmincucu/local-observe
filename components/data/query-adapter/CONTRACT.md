# Query adapter — component contract

Component `query-adapter` (`docs/COMPONENTS.md`). Status **partial**, validation state **experimental
— nothing here has been run against a store**. This document says what the component is, where its
code lives, what it refuses, and what is missing before the row can read `built`.

## There is no `compose.yaml` here, and that is the design

This component starts no container. It is a Python module inside the platform image plus one config
delta to a component that *does* ship a manifest (`components/data/store-signoz/`). A Compose file
here would be a second owner of one `clickhouse` service, and Compose `include` entries do not merge
across entries — an operator following this directory would get either a duplicate-service error or a
service with no image. So:

| Piece | Lives in | Owned by |
| :-- | :-- | :-- |
| The envelope a producer reads (`metrics`/`logs`/`traces`/`refusal`/`reauthorise`) | `local_observe/platform/query.py` | this component |
| The query kinds, the row caps, the receipt/outcome rules | `local_observe/store/client.py` | store facade (port) |
| The SQL and the one HTTP call | `local_observe/store/backends/clickhouse.py` | store facade (port) |
| The read-only ClickHouse users | `components/data/store-signoz/clickhouse-users.d/` | full example gaps (`lo-query`), this component (`lo-read`) |
| The credential mounts and the `${LO_CLICKHOUSE_*}` variables | `components/control/sigma/compose.yaml`, `examples/full/` | those components |

`scripts/check_foundation.py` walks a component directory only through an example's `include` entries.
This directory has no manifest, so nothing in it is reachable that way; the parts that can be checked
statically are checked by naming them — `tests/test_query_adapter.py` runs the XML comparison and the
model check on `lo-read.compose.yaml` directly, which is the same treatment
`components/control/ai/CONTRACT.md` documents for the manifest that example also omits.

## What it gives a producer

`docs/CONTRACTS.md` §2 in one call:

```python
outcome = query.metrics(reader, 'anomaly-producer', 'metric-threshold',
                        window={'start': start, 'end': end},
                        parameters={'resource_id': resource, 'rule_id': rule})
```

returning exactly eight keys, in this order:

| Key | Meaning | On a read that could not happen |
| :-- | :-- | :-- |
| `source` | the producer identity attesting the answer (not a store name — §4) | as supplied |
| `query_type` | the named kind from the closed table | as supplied; `row_limit` is then `0` |
| `parameters` | the approved evidence parameters (§4's seven names) | echoed with any value outside the bounded label shape replaced by `<invalid>` |
| `window` | `{'start','end'}`, UTC half-open `[start,end)`, normalised to the microseconds form `detections.event()` records | as validated; a bad window is a refusal |
| `rows` | JSON-safe mappings (the store row's own fields) | `()` — never a partial page |
| `row_limit` | the kind's bound, i.e. what `truncated` was measured against | the kind's bound, or `0` for a name nothing answers |
| `truncated` | the answer filled the bound, so more exists | `False` |
| `error` | `None`, or the reason | always set |

**The rule those fields exist to keep:** a failed query never returns the same envelope as an empty
result. `error is None` with `rows == ()` is the store's honest "this window has nothing"; any
non-`None` `error` is a failure or an unanswered question, prefixed with the verdict word
(`unavailable: …`) when the store itself said so. `tests/test_query_adapter.py::FailureIsNotEmptySuccess`
is the executable form of that sentence, and `query.refusal(...)` exists so a producer with no reader
at all can emit the same shape instead of emitting nothing.

## What it refuses, and where the refusal comes from

| Refusal | Mechanism | Named by a test |
| :-- | :-- | :-- |
| Caller-supplied SQL | the public functions take a *kind name*; `_read` refuses a statement-shaped name before the store is asked, and the store package builds every statement from `QUERY_SQL` keyed by kind | `test_a_statement_shaped_query_type_never_reaches_the_store` |
| A window intake would reject | `store.client.Window` (reversed, empty, non-text, longer than 7 days) | `test_a_reversed_or_empty_window_is_refused_before_the_store_is_asked` |
| Plaintext `http://` | the moved transport's own endpoint check, honoured here at construction unless `LO_INTERNAL_ALLOW_HTTP=1` | `test_plaintext_http_is_refused_until_the_operator_asks_for_it` |
| An endpoint with embedded credentials, a query string or a fragment | same check | `test_an_endpoint_with_embedded_credentials_is_refused` |
| Missing / blank / unreadable read credential | `open_reader()` returns `None` after **one** WARNING naming the variable; no reader is built | `test_a_missing_credential_names_its_variable_and_not_its_value`, `test_a_blank_credential_refuses_...` |
| Falling back to the Sigma user's credential | there is no code path that reads `LO_CLICKHOUSE_PASSWORD` here | `test_the_runner_credential_is_never_borrowed_for_analysis_reads` |
| Unreachable or refusing store | one envelope with `error` set, one log line, no exception in the caller's loop | `test_a_programming_error_is_not_masked_as_a_store_answer` |
| A value that is not a bounded label, echoed back | `<invalid>` | `test_a_rejected_parameter_value_is_never_echoed_into_the_envelope` |
| A defect in this repository | `NameError`/`RuntimeError` propagate; swallowing them would report a bug as "the store did not answer" | same test as unreachable-store |

**Rows or references, not both at once.** An envelope carries rows for the caller that needs data now.
Proof is a different object and this module does not invent a second one: the facade's
`ReadOutcome.as_evidence(source)` produces the reference `state.validate_event` admits and
`as_sample(...)` the row `Store.put_evidence` retains (`tests/test_store_facade.py::EvidenceSeam`
proves that pair against real intake). `reauthorise()` is the read side of that: it asks the
platform's SQLite what a reference is worth now and takes **no** store client as an argument, so it
cannot re-query the store to make an aged-out link look alive. An expired reference comes back
`expired` with no sample, which is the branch `docs/COMPONENTS.md` §5's "Failure to recovery" scenario
turns on.

## The credential, and why analysis reads do not use the Sigma one

`open_reader()` builds the client from three variables:

| Variable | What it is | If absent |
| :-- | :-- | :-- |
| `LO_CLICKHOUSE_URL` | the endpoint the runner already uses (store boundaries: one store, so no second URL variable) | one WARNING, no reader, coverage events instead of silence |
| `LO_CLICKHOUSE_READ_USER` | the analysis user's name; defaults to `lo-read`, the name `lo-read.xml` creates | the default is used |
| `LO_CLICKHOUSE_READ_PASSWORD` / `..._FILE` | the credential `lo-read.xml` substitutes server-side; `_FILE` preferred (secret files) | one WARNING naming the variable; **no fallback** to `LO_CLICKHOUSE_PASSWORD` |

`lo-read` (`clickhouse-users.d/lo-read.xml`) is `lo-query`'s profile with one number changed:
`max_result_rows` 1 → 2 000, the transport's own `store.client.MAX_ROWS`. It is **not wired**: no
example includes `lo-read.compose.yaml`, and the reader-side mount belongs to
`components/control/sigma/compose.yaml`. Until both land, `open_reader()` refuses and the platform
analysis path stays off, which is the honest state and the one recorded in `conformance.md`.

`docs/COMPONENTS.md` promised "Bounded queries and evidence links". Both halves are now true in code
and neither is proven on a host. `CONTRACT.md` in `clickhouse-users.d/` explains the finding that made
the second user necessary — `lo-query`'s `changeable_in_readonly` marking has made its `1` a default
rather than a ceiling since the facade started sending `bound + 1` — and the two-step order in which
the two profiles may be tightened.

## If this component is off

`docs/COMPONENTS.md`, in its own words: **"UI works; platform analysis unavailable."** Concretely, and
each line is behaviour and not intention:

* SigNoz's UI is untouched. It talks to ClickHouse through its own migration/collector path and never
  through this module (clickstack / hyperdx binds *this* component to tables, not to SigNoz's HTTP APIs).
* `open_reader()` returns `None`. A producer that then calls `query.metrics(None, ...)` or
  `query.refusal(...)` emits an envelope with `error` set; `detections.event()` turns that into a
  `coverage` event, so "no analysis" is visible on the portal rather than inferred from silence.
* The Sigma runner keeps working: it imports its transport from
  `local_observe/store/backends/clickhouse.py` (moved there by store facade, re-exported by
  `platform/sigma_runner.py`) and its `max_result_rows=1` aggregate path is byte-unchanged.
  `tests/test_sigma_runner.py` still passes unmodified.
* Nothing else in the stack notices, because nothing else imports this module yet — `rca`,
  `mcp` and `detections` are the consumers the matrix names, and each is a later item.

## Version and compatibility

[`versions.json`](versions.json) names the compatible tuple §2 asks for: the image pins **by reference**
to `components/data/store-signoz/versions.json` (restating a pin here would be a second copy to drift),
the compiled-mapping identity this path has been tested against, the ClickHouse table and attribute
layouts every statement in `QUERY_SQL` names, and the row caps. It records
`verified_on: null`, because nothing has been verified on a host.

## Validation state

## What is missing before this row can read `built`

1. `lo-read` wired and its `conformance.md` recipes run on a host (three refusals, the row cap, the
   two `system.users` checks).
2. The §5 "Failure to recovery" trace in [`conformance.md`](conformance.md) executed end to end,
   including the expired-evidence branch, with its evidence record filed per `docs/CONTRACTS.md` §6.
3. The reader-side credential mount (`LO_CLICKHOUSE_READ_PASSWORD_FILE`) in the consumer manifest.
4. A decision on `log-records`/`trace-spans` becoming nameable evidence — `state.validate_event`'s
   vocabulary, owned by suppression/correlation, not by this component.
5. A reviewer decision on the ceiling two-step (`clickhouse-users.d/CONTRACT.md`), since either order
   run alone breaks a read.

Runtime acceptance: not-run. Verify the selected store and query-user permissions in your installation.

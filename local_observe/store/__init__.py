"""Bounded reads over the telemetry store, answered as reauthorisable evidence (store facade).

One seam for every platform reader — RCA bundles, anomaly series, forecasts, error budgets and the
assistant's read tools all ask *this* package, and only this package, what the store holds. Without
it each of them invents its own HTTP client and its own idea of a time window.

Three rules give the package its shape:

* **ClickHouse tables, not SigNoz HTTP APIs** (clickstack / hyperdx's phase-1 rule). The only store read this
  repository performs goes to ClickHouse's HTTP interface under a read-only profile; the SigNoz
  query API stays the operator's UI, not the platform's dependency. The tables, the credential and
  every server-side bound are specified in
  ``components/data/store-signoz/CONTRACT.md`` ("Platform read path"), which is the document this
  package implements.
* **A read returns evidence, not a payload.** The result of a query is a reference — query type,
  approved parameters, window, expiry, row count, truncation — that `local_observe.platform.state`
  accepts as an event's evidence and reauthorises on retrieval. Rows travel beside that reference for
  the caller that wants them, and a caller that wants *proof* hands a sample to `Store.put_evidence`.
  Proof outliving the data behind it is refused here rather than discovered at incident time.
* **No caller supplies SQL.** What may be run is a closed table of named query kinds; the SQL lives
  in the backend module. A query kind is the whole public surface, so a stored evidence reference
  can never name a query that cannot be re-run.

**There is deliberately no OpenObserve backend.** store boundaries decided product validation happens with one
datastore, so a second adapter would be untested code that still has to be kept compiling; the ABC
here is the seam that makes a second backend a configuration choice later, not a refactor. The v0.1
tree also carried a SigNoz-HTTP adapter and a retention TTL reader that
``components/data/store-signoz/retention.py`` already owns — neither was ported (store facade).
"""

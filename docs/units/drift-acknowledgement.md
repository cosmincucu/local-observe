# Unit: Drift acknowledgement

**File(s):** `local_observe/platform/drift_ack.py` (the operator's writer) and the acknowledgement half
of `local_observe/platform/configdrift.py` (the record's reader, the resolve rule and the event) ·
**Tests:** `tests/test_drift_ack.py` (the tool: its refusals, its two artifacts, the round trip) and
`tests/test_config_drift.py` (`AcknowledgementReaderTests`, `AcknowledgementResolveTests`,
`AcknowledgementCursorTests`) · **Config:** the optional `acknowledgements` key inside the
`LO_DRIFT_CONFIG` document — **no new environment variable**, and no key means the whole path is off.

Drift acknowledgement lets an operator resolve a reviewed configuration change
without resetting the producer's cursor. This document defines the acknowledgement
record; the [platform guide](../../local_observe/platform/README.md) describes the producer.

## Purpose

Give an operator who has seen a configuration change, checked it and accepted it an **action** that ends
the incident it opened — and make sure that taking that action cannot blind the monitor to the next one.

The producer reports "these bytes are not the bytes I last saw". It never reports "this change is fine",
and it must not start: on a stable round it emits nothing at all, which is what keeps a snapshot tree
from re-firing every five minutes. Closing an incident in this platform takes one thing — a `resolved`
event on the same condition key — and `Store.intake` is the only writer the `incidents` table has. So
the acknowledge path does not close anything itself. It files a durable record, and a **later** round of
the producer turns that record into the ordinary `drift`/`resolved` event that intake closes like any
other producer's.

**The resolve rule, in one sentence:** an incident opened by a drift event closes when, in a *later*
round, the artifact is readable, its current digest equals the digest a human acknowledged in a durable
record, that record names the rule the configuration maps to the artifact *now*, and that exact record
has not been applied before.

What this is **not**: suppression, a snooze, a maintenance window or a rule disable. An acknowledgement
closes one incident for one digest and silences nothing. The rule stays in the configuration, the
artifact stays in the cursor, and the next change opens a new incident with a new delivery. Suppression
is suppression's scope and its own file.

## Why no schema change

The design needed nothing from `local_observe/platform/state.py`, which the programme holds for two
other items. `drift` is already an admitted event kind, `observed-snapshot` an approved evidence
`query_type`, `artifact_sha256` and `rule_id` approved evidence parameters, and the close
(`UPDATE incidents SET status='resolved' …`) already runs for every producer. `VERSION` did not move, no
table was added, no API route was created and no CLI parser changed.

That is also what this design **cannot** do, and the two gaps are named in
[Limits](#limits-that-are-not-bugs) below rather than papered over.

## The rule inside a round

Every artifact gets exactly one word from `ACK_STATES` in the round's `evaluations` row, on both paths
through the loop. The word is reported and never silent, and none of it changes the drift verdict:

| `ack` | meaning | what the round does |
| :-- | :-- | :-- |
| `none` | no `acknowledgements` directory configured, or none filed for this artifact | as if this unit did not exist |
| `stale` | the record names a digest that is **not** the one on disk now | files the drift finding for the current digest; the incident stays open; nothing suppressed |
| `deferred` | the record matches the current digest, but the digest **moved this round** | files only the `firing` event; the resolve waits for the next round |
| `already` | this exact record has already been applied | nothing; a spent acknowledgement is never re-spent |
| `applied` | readable, matching, unspent, stable | files one `drift`/`resolved` event on the firing condition key; the incident closes |
| `refused` | the record could not be read or parsed, or it names another resource, another name, or a rule the configuration no longer maps here | one `WARNING` with a fixed code; the drift verdict is exactly what it would have been |
| `unreadable` | the artifact itself could not be read this round | no acknowledgement is even opened for it; coverage behaves as it always did |

Two of those rows carry the safety of the whole feature:

* **`deferred` exists because of one identifier.** `detections.event` derives
  `source_event_id = digest([rule_id, version, resource_id, window])`. A firing event and a resolve in
  the **same** round carry the same window, so the second would meet
  `old['fingerprint'] != fingerprint` in `Store.intake` and raise `Event retry changed contents` — which
  aborts the whole round, cursor unadvanced, and repeats forever. One event per artifact per round on the
  drift condition is not tidiness, it is the only shape that survives intake. A matching acknowledgement
  found in a round where the digest moved therefore waits; the next round (a new window) applies it.
* **A malformed or stale acknowledgement is never a `coverage` event.** Coverage is a claim about the
  snapshot source — "this producer could not see the artifact". A broken operator instruction is not
  blindness about the artifact, and filing coverage for it would turn a typo into an incident about the
  mount. A `refused` record is one `WARNING` line and no event.

`applied` is remembered. The cursor entry for that artifact gains `ack_applied`, the identity of the
record, and both paths through the round carry it forward — a marker lost during a blind round would
make the next round apply the same acknowledgement again and re-emit a resolve on a condition that is
already closed. An artifact nobody has ever acknowledged keeps the three-key cursor entry it always had.

## The record

One small JSON file per artifact, under the operator's acknowledgement root:

```
<acknowledgements>/<resource_id>/<name>.json
```

```json
{"actor": "operator-one", "artifact_sha256": "<64 hex of the bytes accepted>",
 "at": "2026-08-05T12:07:00.000000+00:00", "name": "running-config",
 "reason": "checked against the change ticket", "resource_id": "<declared UUID>",
 "rule_id": "drift.router-running-config", "schema_version": 1}
```

Eight keys, no more, no fewer (`ACK_KEYS`); file size capped at `MAX_ACK_BYTES` (4096); `reason` is 1 to
`MAX_ACK_REASON_CHARS` (256) characters and holds no control character. `name` is held to
`configdrift.safe_component` — the same rule the configuration's own names pass — and `resource_id`,
`rule_id`, `actor`, `artifact_sha256` and `at` to the platform's existing checks.

**The identity of a record is `digest(record)`**, the canonical-JSON digest of the *validated* document,
not of the bytes on disk. Two consequences are deliberate: whitespace and key order cannot split one
promise into two acknowledgements, and re-acknowledging the same digest at a later `at` is a **new**
record — which is what lets the same artifact be acknowledged twice and a second incident be closed by
the second record.

**What is recorded, durably.** Two things, and the order between them is the design:

1. one append-only audit row, written through the existing public seam `Store.audit` — operation
   `drift.acknowledged`, actor = the named human, subject = the rule id, detail = the record itself. No
   new audit category was needed: `audit_reader.CATEGORIES` is `('all', 'action-transitions')`, so this
   operation appears under `all`.
2. the record file itself, at the path above.

The audit row is written **first**, inside `store.transaction()`, and the file second. An audit row with
no file is an acknowledgement that did not take effect — the incident stays open and re-running the
command files it properly. A file with no audit row is an acknowledgement nobody owns. The first is a
lost click; the second is a forged paper trail.

## The operator's tool

```
python -m local_observe.platform.drift_ack \
  --config /etc/local-observe/drift.json --database /var/lib/local-observe/state.db \
  --resource-id <declared-uuid> --name running-config \
  --sha256 <64 hex> --actor operator-one --reason "checked against the change ticket"
```

`python -m`, not a `lo-platform` subcommand: adding one to `platform/cli.py` is another item's file, and
the producer picks the resolve rule up for free through `configdrift.tick`. The tool imports
`configdrift`; **`configdrift` never imports this module**, so the producer has no dependency on the
door its operator uses.

It runs eight steps in order and refuses on the first one that fails, printing the platform CLI's JSON
contract (`{"status": "error", "error_type": …}`, exit 1) and one `WARNING` carrying a fixed `refusal`
code — never exception text, because an `OSError` message can echo a path:

| `refusal` | why it exists |
| :-- | :-- |
| `no_acknowledgements_directory` | the configuration names no acknowledgement root. The path is off, and the tool will not guess where the file should go |
| `artifact_not_configured` | no configured artifact matches that `--resource-id`/`--name`. A record for something unwatched would sit unread in the tree forever, which is worse than a refusal |
| `database_absent` | `Store(path)` **creates** an empty database. An acknowledgement audited into a file nobody reads records nothing, so a missing `--database` is refused rather than invented |
| `digest_malformed` | `--sha256` is not 64 lowercase hex characters |
| `digest_not_on_disk` | the digest typed is not the one the artifact carries **right now**. An operator can acknowledge only the change they were shown; a record written for bytes nobody can see would close every future revision of that artifact |

Two refusals are not this table's: an unreadable artifact surfaces the reader's own error (a
`FileNotFoundError`, class name only), and a record the reader would refuse — an unbounded `--actor`, a
`--reason` too long — is refused by `configdrift.validate_acknowledgement` before anything is written,
because **the writer must never write what the reader refuses**.

A successful run prints one JSON object (`status`, the artifact key, `rule_id`, `artifact_sha256`, the
record's `acknowledgement_sha256`, the path) and exits 0. The file is written atomically (temporary file
→ fsync → `os.replace`, parent created) with mode `0644`, **not** the cursor's `0600`: the record holds
a digest, a rule, an actor name and one sentence — no configuration text, no credential — and the
process that must read it is the producer, which usually runs as a different account. A private
acknowledgement is an acknowledgement that never takes effect.

The tool never opens the cursor and never asks for `owner.exclusive_owner`: `configdrift.main` holds
that lock for its whole life, so a tool that waited on it would hang and a tool that wrote the cursor
would be a second writer of a single-writer file. This is why an acknowledgement is applied
**eventually**: the resolve lands on the round *after* the one that first sees the record.

## Three things that stop an ack hiding a regression

1. **One exact digest.** The tool refuses to write an acknowledgement for bytes that are not on disk, so
   the operator can only acknowledge the change they were shown.
2. **A stale ack is inert.** It closes nothing, is reported `stale`, and does not suppress the drift
   event for the change that made it stale. `refused` and `unreadable` are equally silent about
   everything except themselves.
3. **Closing restores notification, which is the point.** Once the incident is `resolved`,
   `conditions.incident_id` goes NULL, so the next digest move opens a **new** incident and queues a
   **new** outbox row. Before this unit, an un-closable incident meant the second real change to an
   artifact moved only `updated_at` and `transition` stayed `None` — no outbox row, so the second change
   was delivered to nobody. `test_a_change_after_an_acknowledgement_opens_a_second_incident_and_queues_a_second_delivery`
   pins the outbox sequence `opened → resolved → opened` for exactly that.

## Turning it on, and the cursor trap

Adding `"acknowledgements": "<absolute directory>"` to the configuration document does **not** disturb
an existing cursor. The acknowledgement root is deliberately **not** in `cursor_binding`: that digest is
a statement about *which bytes* a stored digest belongs to, and where an operator files an instruction
says nothing about that. Had it been included, turning acknowledgements on would have changed every
cursor's binding, and `load_cursor` **refuses** a binding mismatch —
`'Drift cursor belongs to a different snapshot tree or artifact set; remove it to re-baseline'` — which
propagates out of `tick`, so `main` logs a warning and repeats the round, and the producer delivers
nothing at all until an operator deletes the cursor, losing every stored digest and re-baselining the
whole tree. Pinned by
`test_turning_acknowledgements_on_does_not_invalidate_an_existing_cursor`, and by the older
`test_a_cursor_from_another_tree_is_refused_rather_than_re_baselined` on the other side of the same rule.

## Reading it back

```sql
SELECT actor, operation, subject, detail FROM audit WHERE operation='drift.acknowledged';
SELECT id, status, opened_at, updated_at FROM incidents WHERE resource_id = ?;
```

| symptom | what it means |
| :-- | :-- |
| a round reports `ack: "none"` and you filed a record | the configuration names no `acknowledgements` root, or the record is not at `<root>/<resource_id>/<name>.json` |
| `stale` on every round | the artifact moved again after the ack. Acknowledge the digest the round reports, or accept that the change is not the one you checked |
| `deferred` for one round, then `applied` | correct. The firing event owned that window |
| `already` forever | the incident was closed and nothing has moved since. This is the steady state after a close |
| `refused` with `code: "ack_not_utf8"`, `"ack_invalid"`, `"ack_unreadable"` or `"ack_rule_mismatch"` | the record is damaged, or it names a resource/name/rule other than the artifact whose path it sits at. Fix the file or re-run the tool; nothing was closed |
| `unreadable` | the artifact could not be read this round, so the record was not even opened. Look at the `error` code on the same row: that is the coverage story |
| an audit row and no file | the run died between them. Re-run it: the second record is a new identity and will be applied |
| a file, an `applied` round, and the incident is still `open` | the close went to the condition key the record produced — check `rule_id` against the configuration, and check that this database is the one the producer posts to |

## Limits that are not bugs

- **The actor is recorded, not authenticated.** There is no local authentication path outside the API,
  and this tool deliberately holds no token: anyone who can run it can attach any bounded name to
  `--actor`. Treat `drift.acknowledged` as *who the operator said they were*, together with whatever the
  host's own access control says about that. Closing the gap needs a role-authenticated path — the
  `state.py` migration and the API route named below — not a bigger string in this tool.
- **The close is attributed to the producer, not to the human.** `Store.intake` is the only writer of
  the `incidents` table, and it names whoever posted the event, so the `events` row and the
  `event.intake` audit row carry the producer's identity. The human appears only in the
  `drift.acknowledged` audit row and in the record. Pinned by
  `tests/test_drift_ack.py::AcknowledgeRoundTripTests::test_an_actor_is_recorded_and_no_more`.
- **This must run where both trees are reachable.** The acknowledgement directory comes from the
  configuration the producer reads, and the audit row goes into the platform database named on the
  command line. Run the tool on a host that can see both — the same host the producer runs on is the
  simple answer — or the acknowledgement will be filed somewhere the producer never looks.
- **The producer never reads the `incidents` table.** It does not know whether anything is open. An
  acknowledgement for an artifact with no open incident files its `resolved` event anyway, intake
  accepts it, and it closes nothing (`incident_id` stays `None`, no outbox row): see
  `test_an_acked_artifact_with_no_open_incident_closes_nothing_and_harms_nothing`.
- **No ack is a gate on anything else.** It does not stop the cursor advancing, does not hide a diff,
  and does not mark an artifact "known good" anywhere: there is no such field in the record's vocabulary.

The `state.py` change that would fix the first two limits is one migration adding
`acknowledged_by`/`acknowledged_at` to `incidents` plus a `Store.acknowledge` method under a human role,
and an API route to reach it. That file is held by suppression (PW3) and correlation (PW4) and the route by event intake.
Two forward notes belong with it: suppression must not treat an acknowledged artifact as **suppressed** (this
closes a condition, it silences nothing), and if correlation groups several condition keys into one incident,
this rule still closes its own condition and correlation decides what the group then does.

## Backup and restore

Both artifacts of an acknowledgement are operator state. The record file is a plain JSON file and is
carried by whatever backs the acknowledgement tree; the audit row is inside the platform database.
Restoring one without the other is coherent in exactly one direction: **database restored, record
absent** means a past acknowledgement is still owned in the audit log and nothing more will happen from
it (nothing is silenced, so nothing is broken); **record restored, database rolled back** means a round
may apply a record whose audit row is gone from the restored window — the close still happens, and the
audit history is what the restore decided to keep. Neither case invents a delivery.

## Running its tests

```
python -B -m unittest tests.test_drift_ack tests.test_config_drift -v
```

Offline, stdlib only, no network and no second process: the platform is the real `Store` on a temp
SQLite file, the tree and the acknowledgement root are temp directories, and every emitted event is
validated by the real `state.validate_event` through the real `Store.intake`. One test
(`test_the_record_is_readable_by_the_account_that_runs_the_producer`) asserts POSIX mode bits and skips
on Windows; the symlink refusal in `tests/test_config_drift.py` skips on a Windows host that withholds
`SeCreateSymbolicLinkPrivilege`.

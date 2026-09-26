# Versioned customisations contract v1

Status: content and scoped runtime release contracts implemented, 2026-09-06.
The platform/Homepage running upgrade rehearsal passes. This is not yet a
whole-installation release manager or a production deployment tool. See
[product philosophy](PRODUCT-PHILOSOPHY.md) for ownership and optional integrations.
Product development stays in Gitea; sanitised releases later go to GitHub under
development and public release authority. User deployment history is separate from both product histories.

## Ownership and storage

The product ships generic defaults, schemas, adapters and supported content.
A user-owned Git directory selects a release and versions its customisations.
Keep these inputs in your deployment repository, separate from the product
tree, following the selected [two-repository layout](OPERATOR-MODEL.md).

Initial versioned inputs:

| Input | Meaning |
|---|---|
| product-content.json | Development content snapshot today; supplied by a pinned product release later. Never edit in place to customise. |
| release.lock.json | Exact content package names, versions and canonical SHA256 digests. Generated draft requires review. |
| runtime-release.json | Product/customisation source hashes, selected image digests, API contracts and platform state compatibility. Separate from the content lock. |
| deployment.json | User content, explicit upstream overrides and Homepage settings. |
| identity-map.json | One-time legacy names/destinations to persistent logical IDs. Backend IDs remain separate. |
| source-hashes.json | Extraction provenance; working-tree hashes are not a committed source revision. |

Native dashboard JSON is retained inside the versioned content definitions and
rendered into individual files. Splitting authoring inputs into referenced files
can be added later; v1 intentionally has one deployment input and no implicit
directory scanning, path imports or extension execution.

Runtime telemetry, databases, cursors, sessions and secret values are NOT content
packages. Keep them in separately backed-up stores. The tile validator rejects
common credential fields unless they use mounted `HOMEPAGE_FILE_*` references;
it is not a complete secret scanner for arbitrary dashboard/query content.
Public export still requires its separate sanitisation gate.

## Stable IDs and reconciliation

- Package records have IDs in their package namespace, such as `core.incidents`.
  User additions use `user.*`. IDs are permanent once committed; changing a
  title, URL, filename or placement must not regenerate them.
- Records currently support groups, tiles and native dashboard documents.
  Display names remain readable; IDs are for reconciliation, not UI labels.
- User content is never silently overwritten by product defaults. Additional
  data-only packages get independent pins and namespaces. Executable plugins,
  lifecycle hooks and automatic package downloads are not supported in v1.
- An override targets a package-owned record and pins the canonical hash of
  `{id, kind, spec}` from that package. `patch` replaces named TOP-LEVEL spec
  fields; nested objects/arrays are replaced whole, never implicitly merged.
  `replace` supplies a complete spec; `disable` removes the record explicitly.
- Any upstream change beneath an override requires review, even when edits
  appear non-overlapping. This conservative v1 rule avoids guessed merges.
- Missing targets, duplicate IDs, incompatible contract versions, wrong hashes,
  ambiguous tile/group names and dangling group references fail closed.
- A user-owned copy gets a new ID and independent history. It does not inherit
  subsequent upstream edits automatically.

The renderer has stable ordering and emits Homepage YAML, dashboard JSON and a
resolved ownership snapshot. A final `files.json` contains raw file hashes.
Outputs must use a new directory; existing configurations are never overwritten.
A failed write can leave an incomplete directory and must not be deployed.
Rendering itself grants no permission to deploy and is not a complete runtime
bundle: mount credentials, runtime/bootstrap policy and integration compatibility
still belong to the deployment adapter.

## Upgrade and UI edits

Upgrade planning compares previous managed content, an independently captured
normalized runtime snapshot, and the candidate. It reports additions, changes,
removals, settings changes, drift and unmanaged content. Edits/deletions to
managed runtime records or collisions with unmanaged records block the plan.
Unmanaged objects remain untouched; removals always require explicit review.
Even a conflict-free plan says `review-required` and `deploy_authorized: false`.

Two separate checks are available. The content planner compares normalized owned
records. The live gate compares independent exports against a reviewed accepted
runtime capture; it does not fabricate logical records from the previous render.
Feeding either check its previous snapshot again is a fixture, not live evidence.

- Homepage: read all nine managed files INSIDE the running container, verify
  its expected image ID and stable container identity, and capture twice to detect
  concurrent edits. Exact raw-byte hashes deliberately treat formatting changes
  as drift. This proves mounted configuration, not successful widgets or queries.
- SigNoz: verified-TLS, GET-only API-key client with redirects/proxies disabled.
  Fully page v2 dashboard lists, fetch and recheck details, preserve v6
  `name/tags/spec/schemaVersion`, and map permanent logical IDs to backend IDs.
  Unknown schemas, incomplete lists, missing mapped dashboards or changes during
  capture fail closed. Unmanaged dashboards are included and block automated
  progression pending review. Sharing/permissions are separate integration state.
- Live snapshots contain scope, time, completeness and artifact hashes. A new
  observation must be at most 60 seconds old and from the same scope/adapter.
  The historical accepted baseline is not required to be recent. A clean result
  is still review-required, never deployment authority.

SigNoz's postable v6 structure is documented in the
[upstream dashboard v2 change](https://github.com/SigNoz/signoz/issues/12177).
Legacy v5 authoring files cannot be compared directly with server-converted v6
documents. First import into an isolated backend and review the normalized export
and backend-ID mapping. Do not automatically bless its first capture as parity.

These APIs offer no cross-service transaction. Double reads reduce inconsistent
captures but do not eliminate a subsequent race. Re-export just before apply and
quiesce UI/config writers for deployment; a production conditional-apply adapter
is still required. The rehearsal owns its isolated writers exclusively.

`export-dashboard` creates a review proposal from supplied normalized JSON. It
does not modify Git, update a server or commit anything. Its observed hash refers
to the resolved record, not necessarily the unmodified upstream package. Review
a user-owned definition edit, or create an explicit package override/copy using
the actual package's base hash. Re-run validation after the change is committed.

## Commands

The original content commands run offline without secret resolution or deployment:

```powershell
.venv/Scripts/python -B -m local_observe.deployment.cli schema deployment
.venv/Scripts/python -B -m local_observe.deployment.cli lock --package examples/deployment/core-v1.yaml
.venv/Scripts/python -B scripts/rehearse_customisations.py --output scratch/migration/rehearsal-new
```

The rehearsal writes reviewable lock files, before/candidate/rollback renders,
an export proposal and reports. Use its generated inputs to exercise the CLI:

```powershell
.venv/Scripts/python -B -m local_observe.deployment.cli render --package scratch/migration/rehearsal-new/package-before.json --lock scratch/migration/rehearsal-new/lock-before.json --deployment scratch/migration/rehearsal-new/deployment.json --output scratch/migration/render-new
.venv/Scripts/python -B -m local_observe.deployment.cli plan --previous scratch/migration/rehearsal-new/before/resolved.json --observed scratch/migration/rehearsal-new/before/resolved.json --candidate scratch/migration/rehearsal-new/candidate/resolved.json
```

The example uses a synthetic observed snapshot deliberately. Exit 2 means a
conflict or invalid input. Exit 0 means successful offline processing, not
approved deployment. Digests check integrity relative to a reviewed lock; they
do not establish publisher authenticity or validate executable code.

Estate content enters these commands only through the operator's own baseline directory:
`scripts/prepare_customisation_candidate.py` (and the `check_migration` gate it shares with
`scripts/check_migration.py`) reads the capture named by `LO_MIGRATION_BASELINE_DIR` or
`--baseline-dir`, the argument winning, and exits 2 with a sentence naming that variable when
neither is set or the directory lacks the file (deployment separation,
[Baseline inputs live in the operator's repository](MIGRATION.md#baseline-inputs-live-in-the-operators-repository)).
The product checkout ships no baseline and holds no default path to one.

It also ships no installation's private names. The preparer takes every deployment name — the deployment identity,
the Homepage source path, the dashboard group prefix, the tiles whose widgets gate a status — from
the `layout` block the capture itself carries, and opens no second operator file: the one input
(`source-layout.json`, in that same directory) is read once, by `scripts/prepare_migration.py`, and
validated there. A capture written before that contract is refused, never guessed at: a schema-1
baseline fails the version check (`Missing versioned source baseline`) and a schema-2 baseline
carrying no layout is refused by the sentence naming the repair (`regenerate it with
prepare_migration.py`). `--source` is required by all three readers: it names the checkout the
capture describes, and the default that used to answer for it pointed at one person's workstation.

## Runtime pins and state

`schema release` emits the strict runtime schema. Product and customisation pins
contain complete selected source-file manifests and a canonical manifest digest.
`snapshot` is allowed only for development; `git` requires a full commit ID.
A public deployment requires committed sources and registry image digests, not
mutable tags or daemon-local image IDs. Commit provenance and publisher trust
are release-process checks, not established merely by typing a commit into JSON.

Every selected image pins its immutable reference, resolved image ID and platform.
The image resolver check must confirm that the reference resolves to that ID on
linux/amd64. `verify-release` checks source bytes and binds deployment/content
metadata to the customisation inputs; it does NOT inspect Docker or a live DB.

The current runtime adapter covers platform SQLite and Homepage. State pins
include actual SQLite application ID, user version and schema hash, with an
integrity check. v1 permits only an unchanged state contract, no implicit migration.
Unknown/new schemas block until explicit migration or restore support is added.
Consistent backups use SQLite's backup API. An online copy made through that API reads over a
read-only connection, which sees only what the database file itself holds until the write-ahead log
is folded back into it — so the copy is consistent only once the WAL is checkpointed, and a sidecar
cannot simply be copied beside it (that is how a truncated snapshot becomes a silent one). That is
why `local_observe.deployment.state_copy.copy_state` refuses a source carrying a live `-wal` unless
the caller names the authority to fold it in (`allow_checkpoint=True`, which writes to the source and
so requires writer exclusion over it). The rehearsal restores a verified
backup, tests the old application, checks durable records, and advances its
last-applied receipt only after candidate acceptance. It never promotes the
existing staging ledgers. Local image IDs used in rehearsal are not portable
public release artifacts.

Additional commands:

```powershell
.venv/Scripts/python -B -m local_observe.deployment.cli schema release
.venv/Scripts/python -B -m local_observe.deployment.cli verify-release --release runtime-release.json --source product-source --customisations observe
.venv/Scripts/python -B -m local_observe.deployment.cli state-gate --previous previous.json --candidate candidate.json --database backup.db
.venv/Scripts/python -B -m local_observe.deployment.cli check-live --previous accepted-snapshot.json --observed fresh-snapshot.json
.venv/Scripts/python -B -m local_observe.deployment.cli export-signoz --url https://signoz.example.test --token-file private/reader-key --identities dashboard-ids.json --output private/export-new
```

`export-homepage --container NAME --image-id sha256:... --scope NAME` emits a
digest-only snapshot to stdout. It uses the explicitly configured local Docker
daemon; it does not discover SSH keys or switch daemon contexts. The SigNoz
export writes potentially private native dashboard definitions into a NEW output
directory; keep it protected and out of the public repository. Do not put tokens
on command lines. Neither export mutates backend content.



## Remaining whole-deployment work

`export-storage --project COMPOSE_PROJECT --scope DAEMON_SCOPE` now inventories
selected projects read-only on the explicitly configured Docker daemon. Repeat
`--project` for each project. It captures image IDs and mount identities twice,
including stopped containers, read-only binds and writable container layers.
It omits environment values and unrelated Docker labels. The snapshot can still
contain private paths; keep it in the downstream deployment's protected evidence.

`schema ownership` emits a recovery-owner declaration schema.
`check-ownership --ownership OWNERS.json --inventory FRESH.json` binds that plan
to the exact inventory digest, requires an observation at most 60 seconds old,
and blocks missing, unknown or duplicate resource assignments. Assign each
resource to a named owner with its recovery method and procedure. A complete
assignment returns review-required with recovery_proven=false. It does not run
backup procedures, authorise deployment or validate their claims. Review existing
resource assignments against each new capture before rebinding its digest.

Writable container layers need an explicit disposable/rebuild/backup decision.
Read-only bind mounts can contain authoritative configuration or credentials, so
they are not silently discarded. Independent hosts, external services, actual
mount contents, vendor state formats, external binaries (including ClickHouse's
histogram executable) and the effective layered Compose inputs still need their
own pins and recovery evidence.
Host-observation mounts such as `/hostfs` must remain externally owned; declaring
`retain-external` does not grant authority to snapshot or restore the host root.

The platform/Homepage adapter is not a full ClickHouse/SigNoz, inventory, scheduler
and witness lifecycle manager. Extend state-owner manifests and migration/restore
gates to those selected components before a whole-stack upgrade. Complete live
dashboard import/query parity, backend IDs, writer-freeze/conditional apply,
portable signed release artifacts and committed downstream history. The current
SigNoz export adapter has protocol tests but no real authenticated export evidence
from this slice. Re-rendering old dashboards is not a telemetry database restore.

Do not migrate production first and defer this compatibility contract until the
public release. A private installation must exercise the same downstream interface as a
future public user, without privileged private imports in product startup.

## Whole-deployment preparation

The owner-plan and runtime-bundle schemas support this preparation;
they do not implement automatic promotion. `lo-deployment schema owner-plan` and
`lo-deployment schema runtime-bundle` expose the contracts. Use `check-owner-plan
--plan PLAN --inventory FRESH_CAPTURE` to bind reviewed service/mount selectors to
actual resources. Physical source changes, new mounts and unobserved external
owners block the gate. `check-runtime --bundle PINS --inventory CAPTURE --owners
PLAN` checks complete service/image/artifact and owner coverage; it is not live
recapture or restore proof. Capture image and artifact identities without exporting environment or credential values.

`verify_git_source` verifies pinned source bytes against actual local Git commit
blobs, not the syntax of a revision field. Build/export exact Git bytes; Windows
line-ending conversion can change the payload even with an unchanged commit.
Its optional `git_directory` identifies the original repository/subdirectory when
verifying a separate byte-exact export. `verify_inputs` requires this Git proof
for Git-kind pins. Snapshot-kind pins remain explicitly development-only evidence.

Both release contracts and whole-runtime bundles record notification safety.
Absent/0 means old unguarded delivery; 1 means the new guard. A normal transition
cannot downgrade 1 to 0 while retaining state. Restoring a pre-upgrade backup in
a network-disabled clone is distinct from exposing guarded live state to an old
notification sender. Per-owner backup/restore, query checks, external ownership,
actual source-to-image provenance and an approved target are still required.

The runtime validator checks each state format/recovery/verification declaration
against its owner plan, and effective configuration against the observed Docker
hash. Preflight requires the previous bundle and compares service scope and state
compatibility. Old captures lacking an effective configuration hash require fresh
observation. Passed receipt fields alone are not verified artifacts: no preflight
result authorises apply or claims whole-stack restore proven.

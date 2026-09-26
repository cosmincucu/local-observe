# Deployment

Review and integrity checks between product releases and private customisations.
Run `python -m local_observe.deployment.cli --help` or `lo-deployment`.

- `content.py`: strict content/ownership schemas, locks, explicit overrides,
  deterministic rendering, three-way drift review and dashboard edit proposals.
- `release.py`: selected source/image pins and platform SQLite compatibility and
  backup checks. The v1 state adapter does not cover vendor databases.
- `live.py`: read-only running Homepage and authenticated SigNoz exports; stable
  IDs, completeness checks and fresh-snapshot drift comparison.
- `dashboard_review.py`: offline saved-export integrity and structural comparison
  against private dashboard authoring. Names panel/variable changes and compares
  supported SQL text by query name; never equates structure with query behavior.
  Full hashes retain unknown fields; dashboard overrides require resolved review.
- `recovery.py`: selected Docker image/mount inventory and recovery-owner coverage.
  Includes read-only binds and writable layers, excludes ephemeral tmpfs mounts.
- `runtime_bundle.py`: complete service/image/config/artifact and state-owner pins;
  file/tree hashes are bounded and secret bytes are never exported by capture.
- `rehearsal.py`: whole-deployment upgrade preflight. Missing ownership, measured
  budgets or per-owner acceptance receipts keep the operation blocked. Requires
  the previous bundle and rejects incompatible scope/service/state changes.
- `state_copy.py`: bounded JSON and online SQLite copies into an exclusive new
  directory, with logical row-content/schema comparison and independent readback.
  Caller owns application writer locks; partial failures remain for inspection.
  A SQLite source whose `-wal` still holds pages is refused, and copied only when
  the caller passes `allow_checkpoint`, which folds that log back in and so writes
  to the source; a `-wal`/`-shm` file is never itself an input. A `.db` copied while
  its sidecar is live opens as an older or empty platform, which no copy check sees.
  This verifies copy integrity, not worker restart or cross-service recovery.
- `cli.py`: offline operations and explicitly requested live reads. No deploy command.

Private host paths and dashboard contents can appear in exports; protect them
and do not publish them as product defaults. Hashes establish integrity relative
to supplied inputs, not publisher trust. An ownership procedure is a declaration,
not a successful restore. Capture races still require a writer freeze and an
immediate recheck before deployment. Independent witness and external services
are outside Docker inventory scope.

Stable owner plans bind project/service/mount selectors to explicit physical
sources, rather than expiring on every container recreate. New mounts, substituted
volumes, duplicate selectors and conflicting shared owners fail closed. External
owners stay unobserved until separately checked. A disposable-layer proposal
still needs writable-layer inspection before acceptance, not a guessed backup.

The runtime bundle is a development observation, not a public release manifest.
It records effective configuration hashes, every selected service image, mounted
source/config trees, Compose/env inputs and the installed histogram executable.
Its product/customisation revisions identify selected authoring inputs; they do
not prove that running bind-mounted source was built from those commits. Independent
recapture and image provenance remain required before promotion. Guard contract 0
marks the unsafe old runtime, and transition back from 1 to 0 is refused.
State format/recovery/verification declarations must exactly match the owner
plan. Service configuration hashes must match the fresh Docker observation;
older inventory exports without that hash need recapture for runtime validation.
Receipt strings and aggregate budget inputs remain supplied evidence, not
independently verified backup artifacts. Preflight never authorises an apply or
claims recovery proven; actual restore verification remains a separate gate.

Contract and commands: [deployment](../../docs/DEPLOYMENT.md).
Tests: `test_deployment.py`, `test_release.py` (including live export contracts) and
`test_recovery.py` under `tests/`; live scripts are opt-in and scoped separately.
`test_dashboard_review.py` covers saved-export tampering, missing/duplicate IDs,
uninterpreted composite queries, unapplied overrides and read-only CLI behavior.

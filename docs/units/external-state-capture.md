# Unit: external discovery and overview capture

`scripts/stage_external_state.py` copies the selected discovery and overview state.
Supply `--base`, `--uid`, `--work` and an existing empty `--output` directory named
`external-state-*` directly under the work directory. The ledgers in that directory identify
the selected state. The configured rootless daemon must remain inside the approved boundary.

The default and `--preflight` inspect without copying. `--capture` explicitly enables backup,
checkpointing where permitted and independent restore readback.

The importable `capture_external_state` defaults to this preflight; explicit `capture=True`
performs the copy. `main` retains rootless setup and requires the existing fresh
`work/external-state-*` root; no service operation occurs on import. The Linux lock
implementation imports `fcntl` only when used, allowing portable fixture tests.

Before capture the orchestrator takes, verifies and publicly records a fresh scoped
backup as required by AGENTS. Capture refuses existing index-backup/backup/restore/report paths,
active discovery, a discovery timer less than 90 seconds away, non-regular or escaped
sources, excessive inputs and an already-owned discovery lock. It never stops a writer
or changes a timer. The production lock is the worker's existing nonblocking owner lock;
injected command/lock seams are for tests, not an alternative production lock policy.

The source set is discovery config/cursor/drift/index, observations and bounded proposals,
plus overview config and its atomic derived output. The discovery service
`LO_DISCOVERY_CONFIG` must equal the ledger-selected configuration before and after
acquiring its lock. Only that allowlisted environment path is extracted; unrelated
environment values are never reported. Discovery exclusion covers observations SQLite WAL
checkpoint and copy. The inventory index has a different writer: live WAL refuses even
in preflight, and capture first takes a separate read-only `index-backup` with checkpointing
forbidden. The remaining capture uses that owned snapshot, never checkpoints the original
index, and retains the extra snapshot on success or failure. Budget additional disk for
that one index copy (at most the existing 64 MiB copy cap). Checkpoint can change source SQLite storage bytes while preserving
logical state; preflight never checkpoints. Overview is read as a separate atomic document,
not as a cross-file-consistent view of its upstream inputs. `copy_state` supplies its
64 MiB/30 second limits, source validation and logical database readback. Each backup is
copied again into a separate restore directory and compared logically. Failed partial
copies remain for diagnosis; there is no automatic retry or cleanup of historical data.

Receipts contain hashes and counts, retain `status=partial`, and explicitly deny application
recovery, loaded-code identity and witness proof. They compare running container identities
before and after capture. Actual discovery/overview process restart, pending proposal/dedupe
verification, witness source/credential recovery and all vendor store restoration remain
required for cards 6/7. Neither this copy nor its offline tests closes whole-stack acceptance.

`tests/test_external_state_capture.py` executes real JSON/SQLite backup and independent
restore on temporary files, with host commands injected. It proves original files preserved,
retired ledger ignored, copy under lock, preflight without writes, active/busy/imminent writer
refusal, missing/corrupt inputs, wrong root and collision refusal. Linux additionally exercises
the real nonblocking lock. No host runtime acceptance is claimed.

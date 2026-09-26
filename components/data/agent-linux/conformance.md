# Linux agent conformance

- Confirm approved read-only mount paths, no engine socket/privileged mode,
  and synthetic-only log inputs before starting on a shared host.
- Compare CPU core count and host metrics with the Linux host, not container
  namespace values. Verify source UUID and hostname appear on stored records.
- Append unique file markers, rotate/truncate/restart, then check offsets and
  stored results. An OTLP synthetic smoke pass does not test the file receiver.
- Interrupt intake, fill a bounded queue, restart with pending state and recover.
  Measure rejected/lost/duplicate records and source-retention requirements.
- Reject bad tokens; remote overlays must validate TLS and trust configuration.
- Rehearse backup/restore and old/new digest upgrade with pending log records.
- Run without RCA, AI, portal, inventory service or security services deployed;
  supplying the declared UUID is still required.

Record evidence per docs/CONTRACTS.md. Windows coverage is not implied by a Linux
pass and remains an integrated-MVP task.

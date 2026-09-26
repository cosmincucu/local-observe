# Inventory conformance

Status: experimental. Runtime results are not-run until recorded for your installation.

- Verify authenticated REST and GraphQL; invalid credentials must be refused.
- Promote and roll back immutable snapshots, recreating the reader each time.
- Confirm UUID and alias continuity after a rename and bounded query behavior.
- Verify the non-root process, read-only mounts, resource limits and loopback binding.
- Back up and restore observed SQLite state; compare records and freshness after restart.
- Rehearse schema and dependency upgrades on isolated copies.
- Exercise provider failure, proposal review and credential rotation.

Record source and configuration pins, commands, results and limitations outside product source.

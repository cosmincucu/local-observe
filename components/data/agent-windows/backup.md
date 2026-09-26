# Backup and restore

Stop only the isolated agent; copy its configuration, executable version/hash and
entire file_storage directory together. Checksum and read back the copied files.
Preserve log input paths and file identity expectations; a changed path can cause
replay. Credentials are a separate protected overlay, never source artifacts.

Copy `versions.json` with them. It is the pin: a restored agent whose `collector.yaml` survived but
whose pin did not cannot be checked by `scripts/check_windows_agent.py`, which refuses to run
without it, and the executable hash in it is the only claim this component has that the binary on
the disk is the binary upstream published.

## What the state directory holds

`LO_AGENT_STATE_DIR` is one directory serving three consumers, so it is one backup unit: the
`filelog` checkpoints, the `otlp_http` persistent export queue, and — with
`collector-security.yaml` selected — the `windows_event_log` receiver bookmarks. Losing it
does not lose telemetry already exported, but it loses *position*: the file receiver re-reads from
`start_at: beginning` (duplicates), and the event-log receiver falls back to its own `start_at:
end`, which silently skips every event raised while the agent was down — for the Security channel
that is an evidence gap that no alert will name. Copy the directory while the agent is stopped, or
the copy is a snapshot taken mid-write.

A second collector process must not be pointed at the same state directory: `file_storage` refuses
it (observed 2026-09-08 as the newcomer dying in exporter startup,
`failed to start "otlp_http" exporter: timeout`; that message names the exporter's config key,
which this component renamed in otlp http alias — the run has not been repeated). Restore into a fresh
directory with its own `LO_AGENT_STATE_DIR`, as below.

Restore into a separate directory/receiver first. Verify expected UUID and queued
marker delivery without touching the installed agent. Process-termination queue
recovery passed; a complete cold copied-state restore remains unexecuted — **not run** for this
component, and the Security bookmark's restore behaviour has never been observed at all, because no
run has been able to read the channel it bookmarks into.

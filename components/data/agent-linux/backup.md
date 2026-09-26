# Agent state recovery

1. Record source UUID, approved file directory, file fingerprints/rotation state,
   collector digest and configuration. Stop producers for the coordinated demo
   checkpoint, let the queue drain where possible, then stop the agent.
2. Snapshot `agent-state` preserving ownership. It contains queue data and file
   offsets, not copies of source log files. Retain matching synthetic source
   files and coordinate with front-door/store checkpoints.
3. Restore into a new volume and separate synthetic directory with the same
   logical file paths inside the container. Use a different project and point
   ingestion only at the restored demo front door.
4. Compare old and new file markers, offsets and stored counts. Test rotated
   files, pending writes and a nonempty exporter queue. Record replay/skip gaps.
5. Do not run restored and original agents against the same source as a normal
   recovery technique. Duplicates and identity collisions would obscure results.

A restored cursor without retained source files does not recover unread logs.
Host metrics missed during downtime are not reconstructed from agent state.

# Intake upgrade

1. Pin the candidate collector digest and review configuration/storage format
   changes from the recorded baseline version.
2. Rehearse on a copied, stopped queue volume, isolated from the original store.
   Run both empty-queue and nonempty-queue cases; preserve exporter IDs.
3. Verify HTTP and gRPC authentication, synthetic redaction canaries, retries,
   queue-full response, restarts and marker reconciliation against the store.
4. Test coordinated token rotation with the demo agent; no unauthenticated grace
   mode. Remote TLS trust must still validate when that overlay is added.
5. Roll back with the prior image/configuration and its pre-upgrade stopped volume
   snapshot, reconciling replay. Never assume old binaries can read new storage.

Record old/new pins and actual results; a collector starting successfully is not
an upgrade or recovery pass.

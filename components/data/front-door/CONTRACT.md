# OTLP front door

OTLP HTTP `127.0.0.1:${LO_OTLP_HTTP_PORT:-14318}` and gRPC
`127.0.0.1:${LO_OTLP_GRPC_PORT:-14317}` require the ingest credential. Both it and the
export credential arrive as mounted files, read by the collector's confmap `file` provider
(`token: ${file:/run/secrets/front-door-ingest-token}` in collector.yaml) rather than by
`${env:...}`: an environment value is visible to `docker inspect` and to
`/proc/<pid>/environ`, and this container runs as root for volume initialisation. The
environment carries only the paths, `LO_INGEST_TOKEN_FILE` and `LO_STORE_TOKEN_FILE`. The
`file` provider returns the file's bytes as written, so each file holds the token and NO
trailing newline — create it with `printf '%s'`, never `echo`, or the newline is sent inside
the `Authorization` header and every push is refused with a 401 that looks like a bad token.
Health is loopback-only on `${LO_INGEST_HEALTH_PORT:-13133}` and is not an ingest test.
Requires digest-qualified `LO_OTEL_IMAGE`. `LO_STORE_OTLP_ENDPOINT` defaults
to the internal SigNoz collector and is reached with a **second, separate**
credential, sent as `Authorization: Bearer` on the export.
No optional-plane dependency.

Two credentials exist because one token would make a single leak write telemetry
end-to-end. Both are **transport auth, not tenant isolation**: every authenticated
writer may assert any `resource_id`, and the store cannot tell them apart.

Evidence for the `${file:...}` form, read rather than inferred: the manifest
`distributions/otelcol-contrib/manifest.yaml` at tag `v0.159.0` of
`open-telemetry/opentelemetry-collector-releases` lists
`go.opentelemetry.io/collector/confmap/provider/fileprovider` among the providers this
distribution resolves `${...}` with, and `confmap/provider/fileprovider/provider.go` at tag
`v0.159.0` of `open-telemetry/opentelemetry-collector` is the `file` scheme's
implementation.

No compose healthcheck is declared here: this component records no image lock, so no
executable inside the collector image is known and a probe command would be a guess.
Liveness is the published `13133` port probed from the host
(`127.0.0.1:${LO_INGEST_HEALTH_PORT:-13133}`), which is a readiness of the listener
only, not of delivery to the store.

The demo uses plaintext only on loopback/the isolated Compose network. Remote
agents require an approved TLS endpoint or verified encrypted tunnel first.
The store and arbitrary workloads must not be reachable through this listener.
The store receiver is credentialed but stays internal; do not publish it as a
shortcut around the front door's redaction and queue.

The project-scoped `front-door-queue` persists exporter queues; bounded capacity
is 3,000 requests per signal, not a disk-byte quota. Retry time is unbounded but
disk/capacity is not. Monitor rejection, queue depth and disk use during tests.
No batch processor precedes this queue. Store acknowledgement still need not
mean durable storage; see the store contract. Delivery may duplicate records.

Known credential and prompt attributes are removed from signal attributes.
This is **not** a universal scrubber: resource attributes, arbitrary log bodies,
new attribute names and nested content need source-specific controls and tests.
Payload capture must remain disabled at sources by default. Do not send real
secrets to test the scrubber; use distinctive synthetic canaries.

Container runs as root for volume initialization, without privileged mode,
host mounts or engine socket. Non-root volume provisioning is a later hardening
check. Token rotation/revocation and TLS are staging gates for remote producers.

See [conformance](conformance.md), [backup](backup.md), [upgrade](upgrade.md).

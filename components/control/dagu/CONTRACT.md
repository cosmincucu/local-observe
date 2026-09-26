# Dagu runner (experimental)

Engine: Dagu 2.16.2, linux/amd64,
`ghcr.io/dagucloud/dagu@sha256:7342d330c8808060c35e17ededf2930eb95f8e7c5f2595366f8a97e91a365725`.
Engine licensing remains upstream's; no source is copied into this product.

Platform owns approvals and execution outcomes. Runner accepts only an existing
approved action, exact action/version/target binding, empty parameters and a
hash-verified immutable DAG. Initial DAG prints a synthetic inspection marker;
no SSH, Docker socket, host mounts, schedules or estate remediation are present.
New actions/parameters need reviewed bindings and conformance fixtures.

Before starting a DAG, persist its platform execution UUID and claim in a private
journal. That UUID is the Dagu run ID. Once a journal exists, only query the run:
never retry start, even after a 404 or uncertain response. Missing/ambiguous
results become unknown for explicit reconciliation. Repeated identical terminal
outcomes with the same executor identity/token are idempotent at the platform.

The live 2.16.2 response envelope is `dagRunDetails`, not the `dagRun` shown in
parts of the [API guide](https://docs.dagu.sh/web-ui/api). An earlier fixture
recorded unknown because of that difference; evidence/history was retained.
DAG definitions must be mounted read-only and unavailable to other writers:
hash checking alone cannot prevent a concurrent spec change before start.

Basic auth on loopback is the isolated rehearsal only. Real overlays require
TLS and a scoped engine identity; do not give an AI/MCP caller engine credentials.
The runner password is not an environment value: Dagu 2.16.2 has no file-only form for
`auth.basic.password`, so it arrives inside a rendered config file that Compose mounts as the
secret `dagu-config` at `/run/secrets/dagu-config`, which `command:` names with
`dagu start-all --config /run/secrets/dagu-config`. `--config` is one of the base flags Dagu adds
to every subcommand. The manifest sets no `DAGU_AUTH_BASIC_PASSWORD` at all, because Dagu binds
that variable to the same key and lets the environment override the file: leaving the binding in
place would put the secret back where `docker inspect` can read it. The username and `auth.mode`
stay in the environment, where an override is harmless. Source read at the pinned tag:
`internal/cmn/config/loader.go` (`envBindings`, `configureViper`), `definition.go` (`AuthDef`,
`AuthBasicDef`) and `internal/cmd/flags.go` (`baseFlags`) in `dagucloud/dagu` tag `v2.16.2`.
Tini is retained, privileged entrypoint user setup is bypassed, and Wiki data is
directed to the writable data volume, separate from read-only DAG files.

No compose healthcheck is declared for `dagu`: the image is pinned by digest in this
file but no image lock is recorded, so no shell or HTTP client inside the engine image
is known and a probe command would be a guess. Liveness is the loopback engine
endpoint (`127.0.0.1:18084`) probed from the host with the runner credential — that
proves the web UI answers, not that a DAG can start.

No compose healthcheck is declared: this component pins its image by digest in this
file but records no image lock, so no shell or HTTP client inside the engine image is
known and a probe command would be a guess. Liveness is the loopback engine endpoint
(`127.0.0.1:18084`) probed from the host with the runner credential; that proves the
web UI answers, not that a DAG can start.

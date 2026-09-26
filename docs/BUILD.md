# Building the component images

Three images build from a checkout of this repository. Run every command from the repository
root: the build context must contain `local_observe/` and the component `requirements.lock`.
Docker is not required to run the test suite, and no image is published; you record a local
image ID and point the component's compose file at it.

## Prerequisites

- Linux container host with Docker (or any builder that supports two-stage builds and
  `COPY --from`). The locks are built for `linux/amd64`, CPython 3.12.
- Network access to PyPI for the default build. An offline host uses the wheel path below.
- Nothing else. There is no registry login and no `scratch/` tree to populate.

## Build the inventory image

    docker build -f components/knowledge/inventory/Dockerfile \
      -t local-observe-inventory:dev .

## Build the platform image

    docker build -f components/control/platform/Dockerfile \
      -t local-observe-platform:dev .

## Build the MCP tool-surface image

    docker build -f components/control/mcp/Dockerfile \
      -t local-observe-mcp:dev .

This one exists because the optional `mcp` extra needs somewhere to live that is not the platform
image: `components/control/platform/Dockerfile` states that the extras are not installed there and
`tests/test_platform_tools.py::ExtraRefusalTests` pins that as behaviour, so the import failure inside
`${LO_PLATFORM_IMAGE}` is the designed degradation (`docs/testing-standards.md`, integration validation) and not a bug to
fix by installing the SDK everywhere. The image is otherwise the platform's shape — same pinned
interpreter, same uid, same two stages, no writable path — plus the pinned SDK and uvicorn. Point
`LO_MCP_IMAGE` at the config ID it prints and see `components/control/mcp/compose.yaml`; nothing in
`examples/` composes that service, so an install that runs no agents never builds this image at all.
The folding-in alternative (one platform image with the extra) is priced in
`components/control/mcp/CONTRACT.md` §6 and was rejected there, not by omission.

All three Dockerfiles take three build arguments:

- `LO_PYTHON_IMAGE` — the base interpreter image. The default is the pinned
  `python:3.12-slim` digest recorded in the component's `versions.json`
  (`python_base`). Override it only to move that pin deliberately, in a change that also
  updates `versions.json`. If the default digest fails to resolve, the base image pin has
  rotted; fix the pin rather than dropping the digest.
- `LO_SOURCE_REVISION` — the source revision the image was built from. Always pass it.
- `LO_IMAGE_SOURCE` — the repository URL. The default is empty, which records "no claimed
  provenance"; set it once the project has a public home.

Pass the provenance arguments in one command:

    docker build -f components/control/platform/Dockerfile \
      --build-arg LO_SOURCE_REVISION="$(git rev-parse HEAD)" \
      --build-arg LO_IMAGE_SOURCE=https://example.invalid/local-observe \
      -t local-observe-platform:dev .

(Use `components/control/mcp/Dockerfile` and `-t local-observe-mcp:dev` for the third image; the
arguments are the same three.)

Verify the labels landed before recording anything:

    docker image inspect local-observe-platform:dev \
      --format '{{json .Config.Labels}}'

## Record the image identity

Build and verify the image before using it. Inspect its identity with:

    docker image inspect local-observe-platform:dev --format '{{.Id}}'

Record the build identity, reviewed source revision and acceptance result in your deployment
repository. Supply the image through the example's required image variable. A local image
config ID does not identify a published registry artifact or establish publisher trust.
Do not add private build receipts or installation metadata to product component manifests.

## Offline build from wheels (optional)

The default build reaches PyPI. On an air-gapped host, download the exact wheels the lock names
on a connected machine (the `pip download` command in "Regenerating a lock" below produces
them), copy the `.whl` files into `components/<area>/<component>/wheels/` in the checkout, and
pass the switch:

    docker build -f components/control/platform/Dockerfile \
      --build-arg OFFLINE_WHEELS=1 -t local-observe-platform:dev .

`OFFLINE_WHEELS` adds `--no-index`, so every wheel the lock needs must be in that directory;
a missing wheel fails the build instead of quietly reaching the network. The install still runs
with `--require-hashes`, so a substituted wheel fails too. That directory is gitignored, is read
only inside the build stage, and never enters the final image; only the installed tree does.

## Regenerating a lock

Each component has `requirements.in` (direct runtime dependencies) and `requirements.lock`
(the transitive closure with a sha256 per artifact). Regenerate a lock when a dependency pin
moves, never by hand. From the repository root, on any machine with Python 3.12 and network:

    python3 -m pip download --dest .wheels-platform \
      --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 \
      --platform manylinux_2_28_x86_64 --platform any \
      --python-version 3.12 --only-binary=:all: --implementation cp \
      -r components/control/platform/requirements.in

Then emit one `name==version` line plus a `--hash=sha256:<digest>` continuation per downloaded
wheel, sorted by package name, keeping the header comment that names the command above:

    for whl in .wheels-platform/*.whl; do
      python3 -m pip hash "$whl"
    done

Hash the wheel you actually resolved for `linux/amd64`; a wheel built for another platform has
a different sha256 and will fail the image build. Use the same command with
`components/knowledge/inventory/requirements.in` and `--dest .wheels-inventory` for the
inventory image. Delete both `.wheels-*` directories afterwards; they are build inputs, not
repository content.

Check the result before committing it. A lock that cannot be satisfied fails here, not on a
host, and `pip` re-verifies every hash against PyPI:

    python3 -m pip download --dest /tmp/lock-check \
      --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 \
      --platform manylinux_2_28_x86_64 --platform any \
      --python-version 3.12 --only-binary=:all: --implementation cp \
      --require-hashes -r components/control/platform/requirements.lock

**The MCP lock is regenerated with `uv`, not with `pip download`.** `mcp` declares
`pywin32; sys_platform == "win32"`, and pip evaluates a requirement's marker against the interpreter it
is *running* rather than the `--platform` it was handed, so the command above asks PyPI for pywin32 and
refuses when run on a Windows host. `uv pip compile --python-platform x86_64-unknown-linux-gnu
--only-binary :all: --generate-hashes` evaluates markers against the target and is the command written in
that lock's own header, run from `components/control/mcp/requirements.in` (the same tool
`components/control/sigma/compiler.lock` was generated by). Two
steps the resolver cannot do for you, and both written in
[`../components/control/mcp/requirements.lock`](../components/control/mcp/requirements.lock): trim the
output to wheels a `python:3.12-slim` linux/amd64 interpreter can load and drop every source distribution
(with an sdist hash in the lock, `--require-hashes` lets the build stage *compile* a package nobody
reviewed), then recompute every remaining hash by downloading the file and hashing the bytes. Then
compare the ten packages this lock shares with the platform's: they must agree on version and on digest.
The lock's own structure — every requirement hash-locked, no Windows-only or extra-only package, the
header's count matching the file, the shared packages matching the platform — is pinned by
`tests/test_mcp_component.py`. The build itself (`pip install --require-hashes` on linux/amd64) is row 1 of
that component's `conformance.md` and has never run.

## What the images contain

The build stage installs the locked packages into an isolated prefix and the runtime stage
copies that prefix into `/usr/local`; no wheel and no pip build cache survives into the final
image. All three images run as uid/gid 65532 with `PYTHONDONTWRITEBYTECODE=1`. The platform image
creates `/data` owned by that uid; the compose file mounts a volume there and runs the
container read-only. The platform image also creates `/state` at mode `0700` owned by that uid since
anomaly deployment support (2026-09-10) — the anomaly producer's cursor parent, which `anomaly_cursor.private_parent`
refuses at any wider mode (`../components/control/anomaly/CONTRACT.md`); **never built here, so
unverified**: the image id recorded in `../components/control/platform/versions.json` predates that
line and carries no `/state` at all, and the check that would settle it is
`../components/control/anomaly/conformance.md` row 2.11. The MCP image creates no writable path at
all: it owns no state, so it declares no
volume and has nothing to back up (`../components/control/mcp/backup.md`). The whole `local_observe`
package is copied into each image because the APIs import each other's modules; in the platform and
inventory images the optional extras (`mcp`, pySigma) are not installed, so importing
`local_observe.platform.mcp` or the Sigma compiler inside those images fails by design. In the MCP image
the `mcp` extra is installed by construction, which is the whole difference between them.

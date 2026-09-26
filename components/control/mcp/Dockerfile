# Two-stage build. Run from the REPOSITORY ROOT so the context carries both the component lock and
# the Python package:
#   docker build -f components/control/mcp/Dockerfile -t local-observe-mcp:dev .
# See docs/BUILD.md, which now names three Dockerfiles and not two.
#
# What this image is for. `local_observe/platform/mcp.py` needs the optional `mcp` extra, and the
# platform image deliberately does not install it (its own Dockerfile says so, and
# tests/test_platform_tools.py::ExtraRefusalTests pins that sentence as a behaviour). Folding the
# extra into the platform image would make the absence invisible in CI — a property
# docs/testing-standards.md protects and integration validation depends on, so an operator who does not run agents
# still boots an image carrying an SDK they never serve. This image is where the extra lives instead:
# the same pinned interpreter base, the same uid, one extra dependency set, one process.
#
# It holds no state and writes nothing. It is a thin authenticated transport over the platform API:
# every read and every proposal leaves this container as an HTTP call made with the *agent's own*
# platform credential, so there is no volume to mount here and no database behind it.
ARG LO_PYTHON_IMAGE=python:3.12-slim@sha256:9c47360a2a0355e2da18516d0b1c2126ec22c195d2185e97347c9d98398c5bef

FROM ${LO_PYTHON_IMAGE} AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Optional offline install: put the linux/amd64 wheels this lock names under
# components/control/mcp/wheels/ (gitignored) and pass --build-arg OFFLINE_WHEELS=1. That switches
# the stage to --no-index, so a missing or substituted wheel fails the build instead of reaching
# PyPI. With the argument unset (the default) this stage installs from PyPI and verifies every
# package against the hashes in the lock. The lock lists wheel hashes only, so a stage that fell
# back to a source distribution would fail the hash check rather than compile something unseen.
ARG OFFLINE_WHEELS=
# The whole component directory, so an offline wheels/ subdirectory arrives with it. Only used in
# this stage; it never reaches the runtime image.
COPY components/control/mcp /tmp/component
RUN python -m pip install \
      --require-hashes \
      --no-cache-dir \
      --prefix=/install \
      ${OFFLINE_WHEELS:+--no-index --find-links=/tmp/component/wheels} \
      -r /tmp/component/requirements.lock

FROM ${LO_PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Provenance, same three arguments docs/BUILD.md passes for the other two images.
# LO_SOURCE_REVISION is the git commit this image was built from; LO_IMAGE_SOURCE is the repository
# URL, deliberately empty until the project has a public home (an empty label records "no claimed
# provenance" rather than a wrong one).
ARG LO_SOURCE_REVISION=unknown
ARG LO_IMAGE_SOURCE=
LABEL org.opencontainers.image.title="local-observe mcp" \
      org.opencontainers.image.description="local-observe MCP tool surface: authenticated read tools and one gated request pair" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="${LO_IMAGE_SOURCE}" \
      org.opencontainers.image.revision="${LO_SOURCE_REVISION}" \
      org.opencontainers.image.base.name="python:3.12-slim" \
      org.opencontainers.image.base.digest="sha256:9c47360a2a0355e2da18516d0b1c2126ec22c195d2185e97347c9d98398c5bef"
WORKDIR /app
COPY --from=build /install /usr/local
# The whole package is copied on purpose, exactly as the platform image does it: this entry point
# imports local_observe.platform.tools (which imports local_observe.platform.state and
# local_observe.inventory.validation), local_observe.http, local_observe.credentials and — when a
# store read is configured — local_observe.platform.query and local_observe.store.*, and the
# topology read opens local_observe.inventory.index. A partial copy would start and then fail on the
# first tool call, which is the worst place to discover a missing module.
COPY local_observe /app/local_observe
# No `RUN mkdir /data`, and no VOLUME: see the note at the head of this file. The process gets a
# read-only configuration bind and a tmpfs /tmp, and owns nothing else.
USER 65532:65532
EXPOSE 8003
# --factory, because app_factory() is where every boot refusal lives: the credential-source
# ambiguity, the identity map's bounds and role rules, and the loud refusal when the extra is
# missing. A container that cannot start is the answer; a server that starts and answers with no
# tools is not. The extra is installed in this image by construction, so that particular refusal
# cannot fire here — it is why the platform image can serve without this one existing.
CMD ["python", "-m", "uvicorn", "local_observe.platform.mcp:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8003", "--no-access-log"]

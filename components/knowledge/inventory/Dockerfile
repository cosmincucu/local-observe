# Two-stage build. Run from the REPOSITORY ROOT so the context carries both the component
# lock and the Python package:
#   docker build -f components/knowledge/inventory/Dockerfile -t local-observe-inventory:dev .
# See docs/BUILD.md. The default build needs only this checkout and PyPI access; an air-gapped
# host can install from a local wheel directory instead (see OFFLINE_WHEELS below).
ARG LO_PYTHON_IMAGE=python:3.12-slim@sha256:9c47360a2a0355e2da18516d0b1c2126ec22c195d2185e97347c9d98398c5bef

FROM ${LO_PYTHON_IMAGE} AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Optional offline install: put the linux/amd64 wheels this lock names under
# components/knowledge/inventory/wheels/ (gitignored) and pass --build-arg OFFLINE_WHEELS=1.
# That switches the stage to --no-index, so a missing or substituted wheel fails the build
# instead of reaching PyPI. With the argument unset (the default) this stage installs from PyPI
# and verifies every package against the hashes in the lock; nothing here needs a checkout-local
# wheel tree.
ARG OFFLINE_WHEELS=
# The whole component directory, so an offline wheels/ subdirectory arrives with it. Only used
# in this stage; it never reaches the runtime image.
COPY components/knowledge/inventory /tmp/component
RUN python -m pip install \
      --require-hashes \
      --no-cache-dir \
      --prefix=/install \
      ${OFFLINE_WHEELS:+--no-index --find-links=/tmp/component/wheels} \
      -r /tmp/component/requirements.lock

FROM ${LO_PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Provenance. LO_SOURCE_REVISION is the git commit this image was built from; LO_IMAGE_SOURCE is
# the repository URL, deliberately empty until the project has a public home (an empty label
# records "no claimed provenance" rather than a wrong one).
ARG LO_SOURCE_REVISION=unknown
ARG LO_IMAGE_SOURCE=
LABEL org.opencontainers.image.title="local-observe inventory" \
      org.opencontainers.image.description="local-observe inventory API: read-only Datasette/GraphQL over a snapshot" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="${LO_IMAGE_SOURCE}" \
      org.opencontainers.image.revision="${LO_SOURCE_REVISION}" \
      org.opencontainers.image.base.name="python:3.12-slim" \
      org.opencontainers.image.base.digest="sha256:9c47360a2a0355e2da18516d0b1c2126ec22c195d2185e97347c9d98398c5bef"
WORKDIR /app
COPY --from=build /install /usr/local
# The whole package is copied on purpose: the inventory API imports local_observe.http and
# local_observe.platform.detection_worker, so a partial copy would not start.
COPY local_observe /app/local_observe
USER 65532:65532
EXPOSE 8001
CMD ["python", "-m", "uvicorn", "local_observe.inventory.api:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8001", "--no-access-log"]

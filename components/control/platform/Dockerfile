# Two-stage build. Run from the REPOSITORY ROOT so the context carries both the component
# lock and the Python package:
#   docker build -f components/control/platform/Dockerfile -t local-observe-platform:dev .
# See docs/BUILD.md. The default build needs only this checkout and PyPI access; an air-gapped
# host can install from a local wheel directory instead (see OFFLINE_WHEELS below).
ARG LO_PYTHON_IMAGE=python:3.12-slim@sha256:9c47360a2a0355e2da18516d0b1c2126ec22c195d2185e97347c9d98398c5bef

FROM ${LO_PYTHON_IMAGE} AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Optional offline install: put the linux/amd64 wheels this lock names under
# components/control/platform/wheels/ (gitignored) and pass --build-arg OFFLINE_WHEELS=1. That
# switches the stage to --no-index, so a missing or substituted wheel fails the build instead
# of reaching PyPI. With the argument unset (the default) this stage installs from PyPI and
# verifies every package against the hashes in the lock; nothing here needs a checkout-local
# wheel tree.
ARG OFFLINE_WHEELS=
# The whole component directory, so an offline wheels/ subdirectory arrives with it. Only used
# in this stage; it never reaches the runtime image.
COPY components/control/platform /tmp/component
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
LABEL org.opencontainers.image.title="local-observe platform" \
      org.opencontainers.image.description="local-observe platform API: jobs, incidents, notifications" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="${LO_IMAGE_SOURCE}" \
      org.opencontainers.image.revision="${LO_SOURCE_REVISION}" \
      org.opencontainers.image.base.name="python:3.12-slim" \
      org.opencontainers.image.base.digest="sha256:9c47360a2a0355e2da18516d0b1c2126ec22c195d2185e97347c9d98398c5bef"
WORKDIR /app
COPY --from=build /install /usr/local
# The whole package is copied on purpose: the platform API imports local_observe.inventory.*
# and the inventory API imports local_observe.platform.detection_worker, so a partial copy
# would not start. Optional extras (mcp, pySigma) are not installed and stay unimported here.
COPY local_observe /app/local_observe
# Evaluation manifests bind these defaults even with explicit operator baselines.
# Retain their exact bytes for quality acceptance inside the component image.
COPY --chmod=0444 examples/inventory/declared.yaml /app/examples/inventory/declared.yaml
COPY --chmod=0444 examples/platform/forecast.yaml /app/examples/platform/forecast.yaml
# Public package code must remain readable/traversable when the build context
# came from a restrictive workstation checkout. No runtime secret is copied here.
# A named volume mounted at a path the image lacks arrives root-owned 0755, which
# anomaly_cursor.private_parent refuses; install -d gives /state the mode and the owner in one call.
RUN chmod -R a+rX /app/local_observe && mkdir /data && chown 65532:65532 /data \
    && install -d -m 0700 -o 65532 -g 65532 /state
USER 65532:65532
EXPOSE 8002
CMD ["python", "-m", "uvicorn", "local_observe.platform.api:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8002", "--no-access-log"]

# Development roadmap

The [product status](../STATUS.md) describes available capabilities. The main remaining release
work is installation and lifecycle validation across the supported component combinations.

1. Validate installation from a clean environment using the reference examples and documented pins.
2. Exercise credential setup, telemetry freshness, inventory discovery and incident workflows.
3. Verify restart, failed-upgrade recovery and complete restore for each selected state owner.
4. Measure optional notification, model and external-service integrations separately.
5. Review release documentation, dependency provenance, licenses, source content and Git metadata.

Track implementation work in the repository issue tracker. Record acceptance against the tested
revision and environment; do not infer release readiness from a task's status or a container's health.
